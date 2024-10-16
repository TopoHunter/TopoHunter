import sys
import os
import common
import redisconn
import kafkaconn
import dbconn
import json
import time
import subprocess
import threading
import shutil
import queue
import ipaddress
import base64
import SubnetTree
import random
from collections import defaultdict
from tqdm import tqdm


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

class Pyasn:
    def __init__(self):
        self.pyasn_tree = SubnetTree.SubnetTree()
        self.fill()
    
    def fill(self):
        with open(common.IPASN_FILE, "r") as f:
            ipasn_content = [line.split() for line in f.read().splitlines() if line[0] != ";"]
            for item in tqdm(ipasn_content):
                prefix, asn = item[0], int(item[1])
                if int(prefix.split("/")[1]) <= 48:
                    self.pyasn_tree[prefix] = [asn, prefix]
        self.pyasn_tree.set_binary_lookup_mode(True)

    def search(self, ip_binary):
        try:
            asn, prefix = self.pyasn_tree[ip_binary[:-1]]
            return asn, prefix
        except:
            return None, None

class AliasedPrefix:
    def __init__(self):
        self.aliased_prefixes_tree = SubnetTree.SubnetTree()
        self.fill()

    def fill(self):
        with open(common.ALIASED_PREFIXES_FILE, "r") as f:
            lines = f.read().splitlines()
            for prefix in tqdm(lines):
                try:
                    self.aliased_prefixes_tree[prefix] = convert_ipv6_to_binary(prefix)
                except ValueError as e:
                    print("Skipped line '" + prefix + "'", file=sys.stderr)
        self.aliased_prefixes_tree.set_binary_lookup_mode(True)

    def search(self, ip_binary):
        try:
            return self.aliased_prefixes_tree[ip_binary[:-1]]
        except:
            return ip_binary
        
class TopoVP:
    def __init__(self):
        common.parse_config()
        self.stop = False
        self.redisconn = redisconn.RedisConn()
        self.dbconn = dbconn.DBConn()
        self.backup_thread = threading.Thread(target=self.backup_files)
        self.files_to_backup = queue.Queue()
        self.files_to_backup_available = threading.Condition()
        self.remote_path = f'~/outputs/{str(common.EXP_ID)}/{common.VP_NAME}/'
        self.kafka_thread = threading.Thread(target=self.kafka_results)
        self.kafkaconn = kafkaconn.KafkaConn(common.VP_NAME)
        self.results_to_communicate = queue.Queue()
        self.results_to_communicate_available = threading.Condition()
        self.pyasn = Pyasn()
        self.aliased_prefix = AliasedPrefix()

    def start(self):
        common.get_logger().info('Start')
        self.backup_thread.start()
        self.kafka_thread.start()
        for msg in self.kafkaconn.cmd_consumer:
            self.process(msg.value)
            if self.stop:
                break

    def process(self, msg: bytes):
        msg_dict = json.loads(msg)
        common.get_logger().info('Processing Command: %s', msg_dict)
        if msg_dict['type'] == common.MSG_TYPE_TRACEROUTE4:
            self.traceroute(msg_dict, 4)
        elif msg_dict['type'] == common.MSG_TYPE_TRACEROUTE6:
            self.traceroute(msg_dict, 6)
        elif msg_dict['type'] == common.MSG_TYPE_STOP:
            self.add_file_to_backup(common.LOG_FILE)
            self.stop = True

    def kafka_results(self):
        while True:
            with self.results_to_communicate_available:
                while self.results_to_communicate.empty():
                    if self.stop:
                        return
                    self.results_to_communicate_available.wait()
                results = self.results_to_communicate.get()
            opr_id, ip_version = results[0], results[1]
            nodes, edges, packets_num = self.parse_yarrp_output(opr_id, common.VP_NAME)
            batch_size = 5000
            low = 0
            while low < len(nodes):
                res_dict = {
                    'type': common.MSG_TYPE_TRACEROUTE4_RESULT if ip_version == 4 else common.MSG_TYPE_TRACEROUTE6_RESULT,
                    'opr_id': opr_id,
                    'nodes': nodes[low: low + batch_size],
                }
                self.kafkaconn.res(res_dict)
                low += batch_size
            common.get_logger().info('opr_id: %s Traceroute Results of Nodes Sent' % (str(opr_id)))
            low = 0
            # we also need to send a message with finished when no edges to send
            if len(edges) == 0:
                res_dict = {
                    'type': common.MSG_TYPE_TRACEROUTE4_RESULT if ip_version == 4 else common.MSG_TYPE_TRACEROUTE6_RESULT,
                    'opr_id': opr_id,
                    'finished': 1,
                    'packets_num': packets_num
                }
                self.kafkaconn.res(res_dict)
            while low < len(edges):
                res_dict = {
                    'type': common.MSG_TYPE_TRACEROUTE4_RESULT if ip_version == 4 else common.MSG_TYPE_TRACEROUTE6_RESULT,
                    'opr_id': opr_id,
                    'edges': edges[low: low + batch_size],
                }
                if low + batch_size >= len(edges):
                    res_dict['finished'] = 1
                    res_dict['packets_num'] = packets_num
                self.kafkaconn.res(res_dict)
                low += batch_size
            common.get_logger().info('opr_id: %s Traceroute Results of Edges Sent' % (str(opr_id)))


    def traceroute(self, msg_dict: dict, ip_version: int = 4):
        common.get_logger().info('Starting Traceroute, IP Version = %d', ip_version)
        opr_id = msg_dict['opr_id']
        while True:
            target_str = self.redisconn.get(f"{common.VP_NAME}:{str(opr_id)}:target")
            if target_str is not None and len(target_str) > 0:
                break
            time.sleep(1)
        self.redisconn.set(f"{common.VP_NAME}:{str(opr_id)}:status", 'P')
        common.get_logger().info('opr_id: %s Status Redis Set to Processing' % (str(opr_id)))        
        targets = target_str.splitlines()
        with open(common.DY6_INPUT_FILE, 'w') as f:
            f.write("\n".join(targets))
        self.call_yarrp(opr_id, common.VP_NAME, ip_version=ip_version)
        common.get_logger().info('opr_id: %s Yarrp Complete' % (str(opr_id)))
        status = self.redisconn.get(f"{common.VP_NAME}:{str(opr_id)}:status")
        if status and status != 'C':
            self.redisconn.set(f"{common.VP_NAME}:{str(opr_id)}:status", 'F')
        common.get_logger().info('opr_id: %s Status Redis Set to Finished' % (str(opr_id)))
        self.add_file_to_backup(common.DY6_PCAP_FILE % (opr_id, common.VP_NAME))
        self.add_file_to_backup(common.DY6_EXCEPTION_FILE % (opr_id, common.VP_NAME))
        self.add_results_to_queue(opr_id, ip_version)

    def call_yarrp(self, opr_id: int, host: str, ip_version: int = 4, pps: int = 5000):
        type_ = "ICMP" if ip_version == 4 else "ICMP6"
        yarrp_id = f"0x{random.randint(0, 0xFFFFFFFF):08x}"
        cmd = "sudo %s -I %s -t %s -r %d -m %d -n %d -y %s -i %s -o %s --pcap %s --exception %s" % (
            common.DY6_PATH, common.INTERFACE_NAME, type_, pps, 16, 8, yarrp_id, common.DY6_INPUT_FILE, 
            common.DY6_OUTPUT_FILE % (opr_id, common.VP_NAME), common.DY6_PCAP_FILE % (opr_id, common.VP_NAME), 
            common.DY6_EXCEPTION_FILE % (opr_id, common.VP_NAME)
        )
        subprocess.run(cmd, shell=True)

    def parse_yarrp_output(self, opr_id: int, host: str) -> tuple:
        topology_dict = dict()  # topology_dict[target_binary][ttl] = [hop_binary, timestamp]
        node_info_dict = dict()    # node_info_dict[hop_binary] = [target_binary, timestamp]
        edge_info_dict = dict() # edge_info_dict[(src_ip, dst_ip)] = [target_binary, hop_distance, timestamp]
        packets_num = 0
        with open(common.DY6_OUTPUT_FILE % (opr_id, common.VP_NAME), "r") as f:
            lines = f.read().splitlines()
        self.add_file_to_backup(common.DY6_OUTPUT_FILE % (opr_id, common.VP_NAME))
        for line in lines:
            try:
                if line[0] != "#":
                    lst = line.split()
                    target = lst[0]
                    timestamp = int(lst[1])
                    ttl = int(lst[5])
                    hop = lst[6]
                    target_binary = convert_ipv6_to_binary(target)
                    hop_binary = convert_ipv6_to_binary(hop)
                    # If target or hop is not a global unicast address, ignore this data.
                    if (target_binary[0] & 0b11110000 != 0b00100000) or (hop_binary[0] & 0b11110000 != 0b00100000):
                        continue
                    # For addresses under aliased prefixes, only record the aliased prefix itself.
                    hop_binary = self.aliased_prefix.search(hop_binary)
                    if target_binary not in topology_dict:
                        topology_dict[target_binary] = dict()
                    if target_binary not in topology_dict:
                        topology_dict[target_binary] = dict()
                    if ttl not in topology_dict[target_binary]:
                        topology_dict[target_binary][ttl] = [hop_binary, timestamp]
                    if hop_binary not in node_info_dict:
                        node_info_dict[hop_binary] = [target_binary, timestamp]
                else:
                    if line.startswith('# Pkts:'):
                        packets_num = int(line[8:])
            except Exception as e:
                print(e)
        for target_binary, trace in topology_dict.items():
            trace = sorted(trace.items(), key=lambda x: x[0])
            for i in range(len(trace) - 1):
                src_ttl, src_hop = trace[i]
                dst_ttl, dst_hop = trace[i + 1]
                src_hop_binary, src_timestamp = src_hop[0], src_hop[1]
                dst_hop_binary, dst_timestamp = dst_hop[0], dst_hop[1]
                if src_hop_binary != dst_hop_binary and ((src_hop_binary, dst_hop_binary) not in edge_info_dict or (dst_ttl - src_ttl) < edge_info_dict[(src_hop_binary, dst_hop_binary)][0]):
                    edge_info_dict[(src_hop_binary, dst_hop_binary)] = [dst_ttl - src_ttl, target_binary, max(src_timestamp, dst_timestamp)]
        node_info_list = [[hop_binary, node_info[0], node_info[1]] for hop_binary, node_info in node_info_dict.items()]
        edge_info_list = [[edge[0], edge[1], edge_info[0], edge_info[1], edge_info[2]] for edge, edge_info in edge_info_dict.items()]
        self.dbconn.insert_nodes(node_info_list, opr_id)
        self.dbconn.insert_edges(edge_info_list, opr_id)
        nodes = [[base64.b64encode(node[0]).decode('utf-8'), base64.b64encode(node[1]).decode('utf-8'), node[2]] for node in self.dbconn.get_nodes(opr_id)]
        edges = [[base64.b64encode(edge[0]).decode('utf-8'), base64.b64encode(edge[1]).decode('utf-8'), edge[2], base64.b64encode(edge[3]).decode('utf-8'), edge[4]] for edge in self.dbconn.get_edges(opr_id)]
        return nodes, edges, packets_num
    
    def backup_files(self):
        while True:
            with self.files_to_backup_available:
                while self.files_to_backup.empty():
                    if self.stop:
                        return
                    self.files_to_backup_available.wait()
                file_path = self.files_to_backup.get()
            try:
                base_name = os.path.basename(file_path)
                compressed_file_path = shutil.make_archive(base_name, 'zip', os.path.dirname(file_path), base_name)
                scp_command = ["scp", compressed_file_path, f"toposerver:{self.remote_path}"]
                start = time.time()
                process = subprocess.Popen(scp_command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                stdout, stderr = process.communicate()
                end = time.time()
                duration = end - start
                if process.returncode == 0:
                    common.get_logger().info(f'{base_name} backup complete, cost {duration}s')
                    remove_command = ["rm", "-f", file_path]
                    subprocess.run(remove_command)
                    remove_command = ["rm", "-f", compressed_file_path]
                    subprocess.run(remove_command)
                else:
                    common.get_logger().info(f'{base_name} backup fails')
            except Exception as e:
                common.get_logger().error("Backup and SCP failed: %s", e)
                
    def add_file_to_backup(self, file_path):
        with self.files_to_backup_available:
            self.files_to_backup.put(file_path)
            self.files_to_backup_available.notify()

    def add_results_to_queue(self, opr_id, ip_version):
        with self.results_to_communicate_available:
            self.results_to_communicate.put([opr_id, ip_version])
            self.results_to_communicate_available.notify()


if __name__ == '__main__':
    topo = TopoVP()
    topo.start()