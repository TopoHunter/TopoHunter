from dbconn import DBConn
from kafkaconn import KafkaConn
from redisconn import RedisConn
# from neo4jconn import Neo4jConn
import time
import common
import json
import threading
from collections import defaultdict
import queue
import ipaddress
import base64
from multiprocessing import Process
from target_value_tree import TargetValueForest
import os
import random


def convert_binary_to_ipv6(ipv6_binary):
    ipv6_address_binary = ipv6_binary[:-1]
    prefix_length_binary = ipv6_binary[-1]
    ipv6_address = ipaddress.IPv6Address(ipv6_address_binary)
    prefix_length = int.from_bytes(prefix_length_binary.to_bytes(1, byteorder='big'), byteorder='big')
    if prefix_length != 128:
        ipv6_str = f"{ipv6_address.compressed}/{prefix_length}"
        return ipv6_str
    else:
        return ipv6_address.compressed


def ipv6_address_to_prefix(ipv6_address, prefix_length):
    try:
        ip_address = ipaddress.IPv6Address(ipv6_address)
        network = ipaddress.IPv6Network((ip_address, prefix_length), strict=False)
        return str(network)
    except ValueError as e:
        return None


class TopoServer:
    def __init__(self, prober_id, prober_name, prober_ip, warmup_targets):
        self.prober_id = prober_id
        self.prober_name = prober_name
        self.prober_ip = prober_ip

        self.kafkaconn = KafkaConn(self.prober_name)
        self.dbconn = DBConn()
        self.redisconn = RedisConn()
        # self.neo4jconn = Neo4jConn()

        self.kafkathread = threading.Thread(target=self.consume_and_save, daemon=True)
        self.processthread = threading.Thread(target=self.process, daemon=True)
        self.commandthread = threading.Thread(target=self.command, daemon=True)
        self.last_command_opr_id = -1
        self.last_processed_opr_id = -1
        os.makedirs(os.path.join(common.EXP_DATA_DIR, self.prober_name), exist_ok=True)
        if os.path.exists(os.path.join(common.EXP_DATA_DIR, self.prober_name, "opr_id.txt")):
            with open(os.path.join(common.EXP_DATA_DIR, self.prober_name, "opr_id.txt"), "r") as f:
                self.last_command_opr_id = int(f.read().splitlines()[0])
        os.makedirs(os.path.join(common.OUTPUTS_DIR, self.prober_name), exist_ok=True)

        self.message_queue = queue.Queue()
        self.message_available = threading.Condition()

        self.current_statics = dict()
        self.forest = TargetValueForest(warmup_targets)

        self.stop_event = threading.Event()
        self.total_packets_num = 0

    def start(self):
        common.get_logger().info('%s Start Running' % (self.prober_name))
        self.kafkathread.start()
        self.processthread.start()
        self.commandthread.start()

    def stop(self):
        self.stop_event.set()
        common.get_logger().info('%s Stop Event Set' % (self.prober_name))
        self.commandthread.join()
        self.processthread.join()
        common.get_logger().info('%s Stop Running' % (self.prober_name))

    def consume_and_save(self):
        cnt = 0
        for msg in self.kafkaconn.res_consumer:
            msg_dict = json.loads(msg.value)
            with self.message_available:
                self.message_queue.put(msg_dict)
                cnt += 1
                if cnt % 100 == 0:
                    common.get_logger().info('%s: %d Messages Received' % (self.prober_name, cnt))
                self.message_available.notify()

    def wait_0(self, opr_id):
        num = 0
        while True:
            if self.forest.probing_stage == 0 or opr_id <= 1:
                break
            else:
                status = self.redisconn.hget(str(opr_id - 2) + ':status', self.prober_name)
                if status and status == 'C':
                    break
                else:
                    if num % 30 == 0:
                        common.get_logger().info('opr_id #%d for Prober #%s: status not completed' % (opr_id - 2, self.prober_name))
            time.sleep(1)
            num += 1
            if num > 60 * 10:
                break

    def wait_1(self, opr_id):
        num = 0
        while True:
            if opr_id == 0:
                break
            else:
                status = self.redisconn.hget(str(opr_id - 1) + ':status', self.prober_name)
                if status and (status == 'F' or status == 'C'):
                    break
                else:
                    if num % 30 == 0:
                        common.get_logger().info('opr_id #%d for Prober #%s: status not finished' % (opr_id - 1, self.prober_name))
            time.sleep(1)
            num += 1
            if num > 60 * 10:
                break

    def command(self):
        while not self.stop_event.is_set():
            try:
                if self.total_packets_num >= common.MAX_PACKETS_NUM_PER_PROBER:
                    self.stop_event.set()
                    break
                opr_id = self.last_command_opr_id + 1
                self.wait_0(opr_id)
                start = time.time()
                if self.forest.probing_stage == 0:
                    seed_targets = self.forest.warmup_allocate()
                    generated_targets = set()
                    end = time.time()
                    common.get_logger().info('[Warmup Stage] Generate targets of opr_id #%d from %s cost %d s, seed_targets: %d, generated_targets: %d' % (opr_id, self.prober_name, end - start, len(seed_targets), len(generated_targets)))
                else:
                    # self.forest.write(os.path.join(common.EXP_DATA_DIR, self.prober_name, "value_forest_before_{}.json".format(str(opr_id))))
                    seed_targets, generated_targets = self.forest.allocate(common.TARGETS_NUM_PER_OPR)
                    end = time.time()
                    common.get_logger().info('[Feedback Stage] Generate targets of opr_id #%d from %s cost %d s, seed_targets: %d, generated_targets: %d' % (opr_id, self.prober_name, end - start, len(seed_targets), len(generated_targets)))
                
                targets = seed_targets | generated_targets
                # 避免卡死
                if len(targets) == 0:
                    targets.add(self.prober_ip)
                with open(os.path.join(common.EXP_DATA_DIR, self.prober_name, "targets_{}.txt".format(str(opr_id))), "w") as f:
                    f.write("\n".join(targets))
                cmd = {"type": "traceroute6", "opr_id": opr_id}
                self.redisconn.hset(str(opr_id) + ':target', self.prober_name, '\n'.join(targets))
                self.redisconn.hset(str(opr_id) + ':status', self.prober_name, 'S')
                self.wait_1(opr_id)
                self.kafkaconn.cmd(cmd)
                self.last_command_opr_id = opr_id
                with open(os.path.join(common.EXP_DATA_DIR, self.prober_name, "opr_id.txt"), "w") as f:
                    f.write(str(self.last_command_opr_id))
            except Exception as e:
                common.get_logger().error("command error: %s" % e)


    def process(self):
        cnt = 0
        while True:
            try:
                with self.message_available:
                    while self.message_queue.empty():
                        self.message_available.wait()
                    msg_dict = self.message_queue.get()
                if msg_dict['type'] == common.MSG_TYPE_TRACEROUTE4_RESULT:
                    self.parse_traceroute_result(msg_dict, 4)
                elif msg_dict['type'] == common.MSG_TYPE_TRACEROUTE6_RESULT:
                    self.parse_traceroute_result(msg_dict, 6)
                cnt += 1
                if cnt % 100 == 0:
                    common.get_logger().info('%s: %d Messages Handled' % (self.prober_name, cnt))  
                if self.stop_event.is_set() and self.last_processed_opr_id != -1 and self.last_processed_opr_id >= self.last_command_opr_id:
                    break
            except Exception as e:
                common.get_logger().error("process error: %s" % e)

    def parse_traceroute_result(self, msg_dict: dict, ip_version: int = 4):
        start = time.time()
        opr_id = int(msg_dict['opr_id'])
        nodes_rcvd = msg_dict.get('nodes', [])
        edges_rcvd = msg_dict.get('edges', [])
        finished = msg_dict.get('finished', 0)
        if len(nodes_rcvd) > 0:
            nodes_rcvd = [[base64.b64decode(item[0].encode('utf-8')), base64.b64decode(item[1].encode('utf-8'))] for item in nodes_rcvd]
            self.dbconn.insert_nodes(nodes_rcvd, opr_id, self.prober_id)
        if len(edges_rcvd) > 0:
            edges_rcvd = [[base64.b64decode(item[0].encode('utf-8')), base64.b64decode(item[1].encode('utf-8')), item[2], base64.b64decode(item[3].encode('utf-8'))] for item in edges_rcvd]
            self.dbconn.insert_edges(edges_rcvd, opr_id, self.prober_id)
            # self.neo4jconn.insert_edges([{"src": convert_binary_to_ipv6(edge[0]), "dst": convert_binary_to_ipv6(edge[1]), "hop_distance": edge[2]} for edge in edges_rcvd], opr_id, ip_version)
            
        if opr_id not in self.current_statics:
            self.current_statics[opr_id] = {"nodes": 0, "edges": 0}
        self.current_statics[opr_id]["nodes"] += len(nodes_rcvd)
        self.current_statics[opr_id]["edges"] += len(edges_rcvd)
        end = time.time()
        common.get_logger().info('Insert results of opr_id #%d from %s cost %d s' % (opr_id, self.prober_name, end - start))

        if finished == 1:
            start = end
            nodes = self.dbconn.get_nodes(opr_id, self.prober_id)
            edges = self.dbconn.get_edges(opr_id, self.prober_id)
            current_point_dict = dict()
            for node in nodes:
                if node[0] != node[1]:
                    target_addr = convert_binary_to_ipv6(node[1])
                    target_prefix = ipv6_address_to_prefix(target_addr, common.TREE_LEAF_PREFIX_LEN)
                    if target_prefix:
                        if target_prefix not in current_point_dict:
                            current_point_dict[target_prefix] = dict()
                        if target_addr not in current_point_dict[target_prefix]:
                            current_point_dict[target_prefix][target_addr] = 0
                        current_point_dict[target_prefix][target_addr] += common.POINT_PER_NODE
            for edge in edges:
                hop_distance = int(edge[3])
                if hop_distance <= 4 and edge[1] != edge[2]:
                    target_addr = convert_binary_to_ipv6(edge[2])
                    target_prefix = ipv6_address_to_prefix(target_addr, common.TREE_LEAF_PREFIX_LEN)
                    if target_prefix:
                        if target_prefix not in current_point_dict:
                            current_point_dict[target_prefix] = dict()
                        if target_addr not in current_point_dict[target_prefix]:
                            current_point_dict[target_prefix][target_addr] = 0
                        current_point_dict[target_prefix][target_addr] += common.POINT_PER_EDGE * (2 ** (1 - hop_distance))
            target_str = self.redisconn.hget(str(opr_id) + ':target', self.prober_name)
            if target_str and len(target_str) > 0:
                targets = target_str.splitlines()
            for target_addr in targets:
                target_prefix = ipv6_address_to_prefix(target_addr, common.TREE_LEAF_PREFIX_LEN)
                if target_prefix not in current_point_dict:
                    current_point_dict[target_prefix] = dict()
                if target_addr not in current_point_dict[target_prefix]:
                    current_point_dict[target_prefix][target_addr] = 0

            self.forest.update(current_point_dict)

            packets_num = msg_dict.get('packets_num', 0)
            self.total_packets_num += packets_num
            common.get_logger().info('Results of opr_id #%d Received from %s: %d nodes, %d new nodes, %d edges, %d new edges, get %.2f point, sent %d packets' %
                                (opr_id, self.prober_name, self.current_statics[opr_id]["nodes"], len(nodes), self.current_statics[opr_id]["edges"], len(edges), sum([sum(value.values()) for value in current_point_dict.values()]), packets_num))
            self.current_statics.pop(opr_id)
            wait_times = 0
            status = self.redisconn.hget(str(opr_id) + ':status', self.prober_name)
            while not status or status != "F":
                time.sleep(0.5)
                status = self.redisconn.hget(str(opr_id) + ':status', self.prober_name)
                wait_times +=1
                if wait_times >= 10:
                    break
            self.redisconn.hset(str(opr_id) + ':status', self.prober_name, "C")
            
            end = time.time()
            common.get_logger().info('Statics of opr_id #%d from %s cost %d s' % (opr_id, self.prober_name, end - start))
            self.last_processed_opr_id = opr_id


def start_server(prober_id, prober_name, prober_ip, warmup_targets):
    server = TopoServer(prober_id, prober_name, prober_ip, warmup_targets)
    try:
        server.start()
        while True:
            if server.total_packets_num >= common.MAX_PACKETS_NUM_PER_PROBER:
                server.stop()
                break
            time.sleep(1)
    except KeyboardInterrupt as e:
        server.stop()


if __name__ == '__main__':
    common.parse_config()
    processes = []
    with open(common.WARMUP_TARGETS_FILE, "r") as f:
        total_warmup_targets = f.read().splitlines()
    random.shuffle(total_warmup_targets)
    total_warmup_targets_num = len(total_warmup_targets)
    warmup_targets_num_per_prober = total_warmup_targets_num // len(common.PROBER_DICT.items())
    for idx, (prober_name, prober_info) in enumerate(common.PROBER_DICT.items()):
        if idx != len(common.PROBER_DICT.items()) - 1:
            warmup_targets = set(total_warmup_targets[idx * warmup_targets_num_per_prober: (idx + 1) * warmup_targets_num_per_prober]) | set(random.sample(total_warmup_targets, warmup_targets_num_per_prober))
        else:
            warmup_targets = set(total_warmup_targets[idx * warmup_targets_num_per_prober: total_warmup_targets_num]) | set(random.sample(total_warmup_targets, warmup_targets_num_per_prober))
        prober_id = prober_info[0]
        prober_ip = prober_info[1]
        process = Process(target=start_server, args=(prober_id, prober_name, prober_ip, warmup_targets))
        process.start()
        processes.append(process)

    try:
        for process in processes:
            process.join()
    except KeyboardInterrupt as e:
        print("Main process interrupted. Exiting.")

