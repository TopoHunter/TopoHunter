from dbconn import DBConn
from kafkaconn import KafkaConn
from redisconn import RedisConn
# from neo4jconn import Neo4jConn
import time
import common
import json
import threading
import queue
import ipaddress
import base64
from multiprocessing import Process
from SubnetTree import SubnetTree
from target_value_tree import TargetValueForest
import os
import random


def convert_binary_to_ipv6(ipv6_binary):
    if len(ipv6_binary) == 17:
        ipv6_address_binary = ipv6_binary[:-1]
        prefix_length = int.from_bytes(ipv6_binary[-1].to_bytes(1, byteorder='big'), byteorder='big')
    else:
        ipv6_address_binary = ipv6_binary
        prefix_length = 128
    ipv6_address = ipaddress.IPv6Address(ipv6_address_binary)
    if prefix_length != 128:
        return f"{ipv6_address.compressed}/{prefix_length}"
    else:
        return ipv6_address.compressed

def convert_ipv6_to_binary(ipv6_str):
    ipv6_str_split = ipv6_str.split("/")
    ip = ipv6_str_split[0]
    if len(ipv6_str_split) == 1:
        prefix_length = 128
    elif len(ipv6_str_split) == 2:
        prefix_length = int(ipv6_str_split[1])
    ipv6_address = ipaddress.IPv6Address(ip)
    ipv6_binary = ipv6_address.packed
    prefix_binary = prefix_length.to_bytes(1, byteorder='big')
    ipv6_binary_with_prefix = ipv6_binary + prefix_binary
    return ipv6_binary_with_prefix


def ipv6_address_to_prefix(ipv6_address, prefix_length):
    try:
        network = ipaddress.IPv6Network((ipv6_address, prefix_length), strict=False)
        return str(network)
    except ValueError as e:
        return None


class TopoServer:
    def __init__(self, vp_id, vp_name, vp_ip):
        self.vp_id = vp_id
        self.vp_name = vp_name
        self.vp_ip = vp_ip

        self.kafkaconn = KafkaConn(self.vp_name)
        self.dbconn = DBConn()
        self.redisconn = RedisConn(self.vp_name)
        # self.neo4jconn = Neo4jConn()

        self.kafkathread = threading.Thread(target=self.receive, daemon=True)
        self.processthread = threading.Thread(target=self.process)
        self.commandthread = threading.Thread(target=self.command)
        self.last_started_opr_id = -1
        self.last_processed_opr_id = -1
        os.makedirs(os.path.join(common.EXP_DATA_DIR, self.vp_name), exist_ok=True)
        if os.path.exists(os.path.join(common.EXP_DATA_DIR, self.vp_name, "opr_id.txt")):
            with open(os.path.join(common.EXP_DATA_DIR, self.vp_name, "opr_id.txt"), "r") as f:
                self.last_started_opr_id = int(f.read().splitlines()[0])
        os.makedirs(os.path.join(common.OUTPUT_DIR, self.vp_name), exist_ok=True)

        self.message_queue = queue.Queue()
        self.message_available = threading.Condition()

        self.current_statics = dict()
        self.forest = TargetValueForest()

        self.stop_event = threading.Event()
        self.complete = False
        # Two stop condition: 1. Reached max packet num, 2. Getting 0 point for several consecutive rounds
        self.total_packets_num = 0
        self.zero_point_rounds = 0

    def start(self):
        common.get_logger().info('%s Start Running' % (self.vp_name))
        self.kafkathread.start()
        self.processthread.start()
        self.commandthread.start()
        self.commandthread.join()
        self.processthread.join()
        common.get_logger().info('%s Stop Running' % (self.vp_name))
        self.complete = True

    def stop(self):
        self.stop_event.set()
        cmd = {"type": common.MSG_TYPE_STOP}
        self.kafkaconn.cmd(cmd)
        common.get_logger().info('%s Stop Event Set' % (self.vp_name))

    def receive(self):
        for msg in self.kafkaconn.res_consumer:
            msg_dict = json.loads(msg.value)
            with self.message_available:
                self.message_queue.put(msg_dict)
                self.message_available.notify()

    def wait_0(self, opr_id):
        num = 0
        while True:
            if opr_id <= 1:
                break
            else:
                status = self.redisconn.get_status(opr_id - 2)
                if status and status == 'C':
                    break
                else:
                    if num % 30 == 0:
                        common.get_logger().info('opr_id #%d for VP #%s: status not completed' % (opr_id - 2, self.vp_name))
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
                status = self.redisconn.get_status(opr_id - 1)
                if status and (status == 'F' or status == 'C'):
                    break
                else:
                    if num % 30 == 0:
                        common.get_logger().info('opr_id #%d for VP #%s: status not finished' % (opr_id - 1, self.vp_name))
            time.sleep(1)
            num += 1
            if num > 60 * 10:
                break

    def command(self):
        while not self.stop_event.is_set():
            try:
                opr_id = self.last_started_opr_id + 1
                self.wait_0(opr_id)
                if self.stop_event.is_set():
                    break
                start = time.time()
                stage, hitlist_targets, generated_targets = self.forest.allocate()
                end = time.time()
                common.get_logger().info('[%s][# %d][Stage %d]: cost %d s, hitlist_targets: %d, generated_targets: %d' % (self.vp_name, opr_id, stage, end - start, len(hitlist_targets), len(generated_targets)))
                targets = hitlist_targets | generated_targets
                if len(targets) == 0:
                    targets.add(self.vp_ip)
                with open(os.path.join(common.EXP_DATA_DIR, self.vp_name, "targets_{}.txt".format(str(opr_id))), "w") as f:
                    f.write("\n".join(targets))
                cmd = {"type": "traceroute6", "opr_id": opr_id}
                self.redisconn.set_target(opr_id, '\n'.join(targets))
                self.redisconn.set_status(opr_id, 'S')
                self.wait_1(opr_id)
                if self.stop_event.is_set():
                    break
                self.kafkaconn.cmd(cmd)
                common.get_logger().info('Send Command: %s', cmd)
                self.last_started_opr_id = opr_id
                with open(os.path.join(common.EXP_DATA_DIR, self.vp_name, "opr_id.txt"), "w") as f:
                    f.write(str(self.last_started_opr_id))
            except Exception as e:
                common.get_logger().error("command error: %s" % e)
        common.get_logger().info('%s Command Stop' % self.vp_name)

    def process(self):
        while True:
            if self.stop_event.is_set() and self.last_processed_opr_id != -1 and self.last_processed_opr_id >= self.last_started_opr_id:
                common.get_logger().info('%s Process Stop' % self.vp_name)
                return
            try:
                with self.message_available:
                    while self.message_queue.empty():
                        if self.stop_event.is_set() and self.last_processed_opr_id != -1 and self.last_processed_opr_id >= self.last_started_opr_id:
                            common.get_logger().info('%s Process Stop' % self.vp_name)
                            return
                        self.message_available.wait(1)
                    msg_dict = self.message_queue.get()
                if msg_dict['type'] == common.MSG_TYPE_TRACEROUTE4_RESULT:
                    self.parse_traceroute_result(msg_dict, 4)
                elif msg_dict['type'] == common.MSG_TYPE_TRACEROUTE6_RESULT:
                    self.parse_traceroute_result(msg_dict, 6)
                if self.stop_event.is_set() and self.last_processed_opr_id != -1 and self.last_processed_opr_id >= self.last_started_opr_id:
                    common.get_logger().info('%s Process Stop' % self.vp_name)
                    return
            except Exception as e:
                common.get_logger().error("process error: %s" % e)

    def parse_traceroute_result(self, msg_dict: dict, ip_version: int = 4):
        start = time.time()
        opr_id = int(msg_dict['opr_id'])
        nodes_rcvd = msg_dict.get('nodes', [])
        edges_rcvd = msg_dict.get('edges', [])
        finished = msg_dict.get('finished', 0)
        if len(nodes_rcvd) > 0:
            nodes_rcvd = [[base64.b64decode(item[0].encode('utf-8')), base64.b64decode(item[1].encode('utf-8')), item[2]] for item in nodes_rcvd]
            self.dbconn.insert_nodes(nodes_rcvd, opr_id, self.vp_id)
        if len(edges_rcvd) > 0:
            edges_rcvd = [[base64.b64decode(item[0].encode('utf-8')), base64.b64decode(item[1].encode('utf-8')), item[2], base64.b64decode(item[3].encode('utf-8')), item[4]] for item in edges_rcvd]
            self.dbconn.insert_edges(edges_rcvd, opr_id, self.vp_id)
            # self.neo4jconn.insert_edges([{"src": convert_binary_to_ipv6(edge[0]), "dst": convert_binary_to_ipv6(edge[1]), "hop_distance": edge[2]} for edge in edges_rcvd], opr_id, ip_version)
        if opr_id not in self.current_statics:
            self.current_statics[opr_id] = {"nodes": 0, "edges": 0}
        self.current_statics[opr_id]["nodes"] += len(nodes_rcvd)
        self.current_statics[opr_id]["edges"] += len(edges_rcvd)
        end = time.time()
        common.get_logger().info('Insert results of opr_id #%d from %s cost %d s' % (opr_id, self.vp_name, end - start))
        if finished == 1:
            start = end
            nodes = self.dbconn.get_nodes(opr_id, self.vp_id)
            edges = self.dbconn.get_edges(opr_id, self.vp_id)
            point_dict = dict()
            for node in nodes:
                if node[0] != node[1]:
                    if node[1] not in point_dict:
                        point_dict[node[1]] = 0
                    point_dict[node[1]] += common.POINT_PER_NODE
            for edge in edges:
                hop_distance = int(edge[2])
                if hop_distance <= 4 and edge[0] != edge[3] and edge[1] != edge[3]:
                    if edge[3] not in point_dict:
                        point_dict[edge[3]] = 0
                    point_dict[edge[3]] += common.POINT_PER_EDGE * (2 ** (1 - hop_distance))
            target_str = self.redisconn.get_target(opr_id)
            if target_str and len(target_str) > 0:
                targets = target_str.splitlines()
            for target in targets:
                target_binary = convert_ipv6_to_binary(target)
                if target_binary not in point_dict:
                    point_dict[target_binary] = 0
            self.forest.update(point_dict)
            packets_num = msg_dict.get('packets_num', 0)
            self.total_packets_num += packets_num
            common.get_logger().info('Results of opr_id #%d Received from %s: %d nodes, %d new nodes, %d edges, %d new edges, get %.2f point, sent %d packets' %
                                (opr_id, self.vp_name, self.current_statics[opr_id]["nodes"], len(nodes), self.current_statics[opr_id]["edges"], len(edges), sum(point_dict.values()), packets_num))
            self.current_statics.pop(opr_id)
            wait_times = 0
            status = self.redisconn.get_status(opr_id)
            while not status or status != "F":
                time.sleep(0.5)
                status = self.redisconn.get_status(opr_id)
                wait_times += 1
                if wait_times >= 10:
                    break
            self.redisconn.set_status(opr_id, 'C')
            end = time.time()
            common.get_logger().info('Statics of opr_id #%d from %s cost %d s' % (opr_id, self.vp_name, end - start))
            self.last_processed_opr_id = opr_id
            if sum(point_dict.values()) == 0:
                self.zero_point_rounds += 1
            else:
                self.zero_point_rounds = 0
            if self.zero_point_rounds >= common.MAX_ZERO_POINT_ROUNDS or self.total_packets_num + packets_num >= common.MAX_PACKETS_NUM_PER_VP:
                if not self.stop_event.is_set():
                    self.stop()


def start_server(vp_id, vp_name, vp_ip):
    server = TopoServer(vp_id, vp_name, vp_ip)
    try:
        server.start()
        while not server.complete:
            time.sleep(1)
    except KeyboardInterrupt as e:
        server.stop()


if __name__ == '__main__':
    common.parse_config()
    processes = []
    for vp_name, vp_info in common.VP_DICT.items():
        vp_id = vp_info[0]
        vp_ip = vp_info[1]
        process = Process(target=start_server, args=(vp_id, vp_name, vp_ip))
        process.start()
        processes.append(process)
    try:
        for process in processes:
            process.join()
    except KeyboardInterrupt as e:
        print("Main process interrupted. Exiting.")

