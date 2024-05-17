import sys
import os
import common
import redisconn
import kafkaconn
import dbconn
import json
import time
import subprocess
import psutil
import threading
import shutil
import pyasn
import queue
import ipaddress
import base64
import SubnetTree
import random
from collections import defaultdict


def kill_proc_tree(pid, including_parent=True):
    try:
        parent = psutil.Process(pid)
    except psutil.NoSuchProcess:
        return
    children = parent.children(recursive=True)
    for child in children:
        child.kill()
    psutil.wait_procs(children, timeout=5)
    if including_parent:
        parent.kill()
        parent.wait(5)


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
    ipv6_address_binary = ipv6_binary[:-1]
    prefix_length_binary = ipv6_binary[-1]
    ipv6_address = ipaddress.IPv6Address(ipv6_address_binary)
    prefix_length = int.from_bytes(prefix_length_binary.to_bytes(1, byteorder='big'), byteorder='big')
    if prefix_length != 128:
        ipv6_str = f"{ipv6_address.compressed}/{prefix_length}"
        return ipv6_str
    else:
        return ipv6_address.compressed

class TopoClient:
    def __init__(self):
        common.parse_config()
        self.redisconn = redisconn.RedisConn()
        self.dbconn = dbconn.DBConn()
        self.backup_thread = threading.Thread(target=self.backup_files, daemon=True)
        self.files_to_backup = queue.Queue()
        self.files_to_backup_available = threading.Condition()
        self.kafka_thread = threading.Thread(target=self.kafka_results, daemon=True)
        self.results_to_communicate = queue.Queue()
        self.results_to_communicate_available = threading.Condition()
        local_hostname = subprocess.check_output(['hostname']).decode('utf-8').strip()
        self.client_position = local_hostname.split('-')[-2]
        self.kafkaconn = kafkaconn.KafkaConn(self.client_position)
        exp_num = str(common.EXP_NUM)
        self.remote_path = f'~/outputs/{exp_num}/{self.client_position}/'
        self.iana_allocated_prefixes = pyasn.pyasn('./data/iana_allocated_prefix.dat')
        self.pyasn_tree = SubnetTree.SubnetTree()
        self.fill_pyasn_tree()
        self.covered_bgp_prefixes = set()
        self.aliased_tree = SubnetTree.SubnetTree()
        self.fill_aliased_tree()
        self.split_ttl_tree = SubnetTree.SubnetTree()
        self.bgp_prefix_split_ttl_dict = dict()
        self.nodes_db_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "nodes.db")
        
    def fill_aliased_tree(self):
        with open(common.ALIASED_PREFIXES_FILE, "r") as f:
            lines = f.read().splitlines()
            for prefix in lines:
                try:
                    self.aliased_tree[prefix] = convert_ipv6_to_binary(prefix)
                except ValueError as e:
                    print("Skipped line '" + prefix + "'", file=sys.stderr)
        self.aliased_tree.set_binary_lookup_mode(True)

    def fill_pyasn_tree(self):
        with open(common.IPASN_FILE, "r") as f:
            ipasn_content = [line.split() for line in f.read().splitlines() if line[0] != ";"]
            for item in ipasn_content:
                prefix, asn = item[0], int(item[1])
                self.pyasn_tree[prefix] = [asn, prefix]
        self.pyasn_tree.set_binary_lookup_mode(True)
                    
    def search_aliased_tree(self, ip_binary):
        try:
            return self.aliased_tree[ip_binary[:-1]]
        except:
            return ip_binary

    def search_pyasn_tree(self, ip_binary):
        try:
            asn, prefix = self.pyasn_tree[ip_binary[:-1]]
            return asn, prefix
        except:
            return None, None

    def insert_split_ttl_tree(self, prefix, ttl):
        prefix_length = int(prefix.split("/")[1])
        try:
            old_ttl, plen = self.split_ttl_tree[prefix]
            if plen != prefix_length or ttl < old_ttl:
                self.split_ttl_tree[prefix] = [ttl, prefix_length]
        except:
            self.split_ttl_tree[prefix] = [ttl, prefix_length]
        
    def update_split_ttl_tree(self, ttl_dict):
        to_update_dict = dict()
        for ip_binary, ttl in ttl_dict.items():
            prefix_length_binary = ip_binary[-1]
            prefix_length = int.from_bytes(prefix_length_binary.to_bytes(1, byteorder='big'), byteorder='big')
            bgp_asn, bgp_prefix = self.search_pyasn_tree(ip_binary)
            if bgp_prefix:
                bgp_prefix_length = int(bgp_prefix.split("/")[1])
                if bgp_prefix in to_update_dict:
                    to_update_dict[bgp_prefix] = min(to_update_dict[bgp_prefix], ttl)
                else:
                    to_update_dict[bgp_prefix] = ttl
            else:
                bgp_prefix_length = 0
            ip_address = ipaddress.IPv6Address(ip_binary[:-1])
            for plen in [32, 48]:
                if bgp_prefix_length < plen <= prefix_length:
                    update_prefix = str(ipaddress.IPv6Network((ip_address, plen), strict=False))
                    if update_prefix in to_update_dict:
                        to_update_dict[update_prefix] = min(to_update_dict[update_prefix], ttl)
                    else:
                        to_update_dict[update_prefix] = ttl
        for prefix, ttl in to_update_dict.items():
            self.insert_split_ttl_tree(prefix, ttl)
    
    def get_split_ttl(self, ip):
        ip_binary = convert_ipv6_to_binary(ip)
        try:
            ttl, plen = self.split_ttl_tree[ip]
            return ttl, "tree"
        except:
            asn, prefix = self.search_pyasn_tree(ip_binary)
            if prefix and prefix in self.bgp_prefix_split_ttl_dict:
                return self.bgp_prefix_split_ttl_dict[prefix], "dict"
            return random.randint(6, 16), "random"

    def get_local_host4(self) -> str:
        return common.LOCAL_IPV4_ADDR

    def get_local_host6(self) -> str:
        return common.LOCAL_IPV6_ADDR

    def start(self):
        common.get_logger().info('Start')
        self.backup_thread.start()
        self.kafka_thread.start()
        for msg in self.kafkaconn.cmd_consumer:
            self.process(msg.value)

    def process(self, msg: bytes):
        msg_dict = json.loads(msg)
        common.get_logger().info('Processing Command: %s', msg_dict)
        if msg_dict['type'] == common.MSG_TYPE_TRACEROUTE4:
            self.traceroute(msg_dict, 4)
        elif msg_dict['type'] == common.MSG_TYPE_TRACEROUTE6:
            self.traceroute(msg_dict, 6)

    def kafka_results(self):
        while True:
            with self.results_to_communicate_available:
                while self.results_to_communicate.empty():
                    self.results_to_communicate_available.wait()
                results = self.results_to_communicate.get()
            opr_id, nodes, edges, packets_num, ip_version = results[0], results[1], results[2], results[3], results[4]
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
            target_str = self.redisconn.hget(str(opr_id) + ':target', self.client_position)
            if target_str is not None and len(target_str) > 0:
                break
            time.sleep(10)

        self.redisconn.hset(str(opr_id) + ':status', self.client_position, 'P')
        common.get_logger().info('opr_id: %s Status Redis Set to Processing' % (str(opr_id)))        
        targets = target_str.splitlines()
        target_split_ttl_list = []
        split_ttl_source = defaultdict(int)
        for target in targets:
            split_ttl, source = self.get_split_ttl(target)
            split_ttl_source[source] += 1
            target_split_ttl_list.append([target, split_ttl])
        common.get_logger().info('opr_id: %s, get split_ttl: from tree: %d, from dict: %d, from random: %d' % (str(opr_id), split_ttl_source["tree"], split_ttl_source["dict"], split_ttl_source["random"]))
        with open(common.YARRP_INPUT_DIR, 'w') as f:
            for item in target_split_ttl_list:
                f.write(item[0] + " " + str(item[1]) + "\n")
        self.call_yarrp(opr_id, self.client_position, ip_version=ip_version)
        common.get_logger().info('opr_id: %s Yarrp Complete' % (str(opr_id)))
        self.add_file_to_backup(common.YARRP_OUTPUT_DIR % (opr_id, self.client_position))
        self.add_file_to_backup(common.PCAP_OUTPUT_DIR % (opr_id, self.client_position))
        nodes, edges, packets_num = self.parse_yarrp_output(opr_id, self.client_position)
        self.add_results_to_queue(opr_id, nodes, edges, packets_num, ip_version)
        status = self.redisconn.hget(str(opr_id) + ':status', self.client_position)
        if status and status != 'C':
            self.redisconn.hset(str(opr_id) + ':status', self.client_position, 'F')
        common.get_logger().info('opr_id: %s Status Redis Set to Finished' % (str(opr_id)))

    def call_yarrp(self, opr_id: int, host: str, ip_version: int = 4, pps: int = 5000):
        if ip_version == 4:
            cmd = 'sudo %s -A %s -I %s -t ICMP -r %d -o %s -f %s -m 32 --sqlite %s' % (
                common.YARRP_DIR, common.YARRP_INPUT_DIR, common.INTERFACE_NAME, pps, common.YARRP_OUTPUT_DIR % (opr_id, self.client_position), common.PCAP_OUTPUT_DIR % (opr_id, self.client_position), self.nodes_db_path)
        else:
            cmd = 'sudo %s -A %s -I %s -t ICMP6 -r %d -o %s -f %s -m 32 --sqlite %s' % (
                common.YARRP_DIR, common.YARRP_INPUT_DIR, common.INTERFACE_NAME, pps, common.YARRP_OUTPUT_DIR % (opr_id, self.client_position), common.PCAP_OUTPUT_DIR % (opr_id, self.client_position), self.nodes_db_path)
        process = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        try:
            stdout, stderr = process.communicate(timeout=1200)
        except Exception as e:
            common.get_logger().error(e)
            try:
                kill_proc_tree(process.pid)
            except Exception as ex:
                common.get_logger().error(e)
            stdout, stderr = process.communicate()

    def parse_yarrp_output(self, opr_id: int, host: str) -> tuple:
        topology_dict = dict()
        node_set = set()  # store node in binary
        edge_dict = dict()  # (src, dst) -> hop_distance
        target_dict = dict()  # node / (src, dst) -> target
        ttl_dict = dict()   # node -> min_ttl
        packets_num = 0

        with open(common.YARRP_OUTPUT_DIR % (opr_id, host), 'r') as f:
            lines = f.read().splitlines()
            for line in lines:
                if line[0] != '#':
                    try:
                        lst = line.split()
                        ttl = int(lst[5])
                        # If the TTL is not between [1,32], ignore this data.
                        if ttl < 1 or ttl > 32:
                            continue
                        target = lst[0]
                        hop = lst[6]
                        target_binary = convert_ipv6_to_binary(target)
                        hop_binary = convert_ipv6_to_binary(hop)
                        # If target or hop is not a global unicast address, ignore this data.
                        if target_binary[0] & 0b11110000 != 0b00100000:
                            continue
                        if hop_binary[0] & 0b11110000 != 0b00100000:
                            continue
                        # Update covered_bgp_prefixes
                        hop_asn, hop_prefix = self.search_pyasn_tree(hop_binary)
                        if hop_prefix:
                            self.covered_bgp_prefixes.add(hop_prefix)
                        # For addresses under aliased prefixes, only record the aliased prefix itself.
                        hop_binary = self.search_aliased_tree(hop_binary)
                        if hop_binary in ttl_dict:
                            ttl_dict[hop_binary] = min(ttl, ttl_dict[hop_binary])
                        else:
                            ttl_dict[hop_binary] = ttl
                        # Add to records
                        node_set.add(hop_binary)
                        if hop_binary not in target_dict:
                            target_dict[hop_binary] = target_binary
                        if target_binary not in topology_dict.keys():
                            topology_dict[target_binary] = dict()
                        topology_dict[target_binary][ttl] = hop_binary
                    except:
                        pass
                else:
                    if line.startswith('# Pkts:'):
                        packets_num = int(line[8:])

        for (target_binary, v) in topology_dict.items():
            trace = sorted(v.items(), key=lambda x: x[0])
            target_asn, target_prefix = self.search_pyasn_tree(target_binary)
            if target_prefix and target_prefix not in self.covered_bgp_prefixes:
                stop_ttl = trace[-1][0]
                # If there is a loopback in the traceroute path, truncate it.
                met_ips = set()
                for i in range(len(trace)):
                    ttl, ip = trace[i]
                    if ip in met_ips:
                        stop_ttl = ttl
                        break
                    else:
                        met_ips.add(ip)
                if target_prefix not in self.bgp_prefix_split_ttl_dict or self.bgp_prefix_split_ttl_dict[target_prefix] < stop_ttl:
                    self.bgp_prefix_split_ttl_dict[target_prefix] = stop_ttl
            for i in range(len(trace) - 1):
                src_ttl, src = trace[i]
                dst_ttl, dst = trace[i + 1]
                if src == dst:
                    continue
                if (src, dst) not in edge_dict or dst_ttl - src_ttl < edge_dict[(src, dst)]:
                    edge_dict[(src, dst)] = dst_ttl - src_ttl
                    target_dict[(src, dst)] = target_binary

        nodes = []
        self.dbconn.insert_nodes(list(node_set), opr_id)
        new_nodes = [record[0] for record in self.dbconn.get_nodes(opr_id)]
        ttl_dict = {node: ttl_dict[node] for node in new_nodes}
        self.update_split_ttl_tree(ttl_dict)
        for node in new_nodes:
            try:
                # 0: node_addr, 1: target_addr
                nodes.append([base64.b64encode(node).decode('utf-8'), base64.b64encode(target_dict[node]).decode('utf-8')])
            except:
                continue

        edges = []
        edge_list = [[src, dst, hop_distance] for (src, dst), hop_distance in edge_dict.items()]
        self.dbconn.insert_edges(edge_list, opr_id)
        edge_list = self.dbconn.get_edges(opr_id)
        for edge in edge_list:
            try:
                # 0: src_addr, 1: dst_addr, 2: hop_distance, 3: target_addr
                edges.append([base64.b64encode(edge[0]).decode('utf-8'), base64.b64encode(edge[1]).decode('utf-8'), edge[2], base64.b64encode(target_dict[(edge[0], edge[1])]).decode('utf-8')])
            except:
                continue
        return nodes, edges, packets_num
    
    def backup_files(self):
        while True:
            with self.files_to_backup_available:
                while self.files_to_backup.empty():
                    self.files_to_backup_available.wait()
                file_path = self.files_to_backup.get()
            try:
                base_name = os.path.basename(file_path)
                shutil.make_archive(base_name, 'zip', os.path.dirname(file_path), base_name)
                compressed_file_path = base_name + '.zip'
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

    def add_results_to_queue(self, opr_id, nodes, edges, packets_num, ip_version):
        with self.results_to_communicate_available:
            self.results_to_communicate.put([opr_id, nodes, edges, packets_num, ip_version])
            self.results_to_communicate_available.notify()


if __name__ == '__main__':
    topo = TopoClient()
    topo.start()