import SubnetTree
import pyasn
import os
import argparse
from tqdm import tqdm
from collections import defaultdict


parser = argparse.ArgumentParser()
parser.add_argument("-i", type=str)
parser.add_argument("-a", type=str)
parser.add_argument("-f", type=str)
parser.add_argument("-o", type=str)
args = parser.parse_args()


ipasn_file = args.i
with open(ipasn_file, "r") as f:
    bgp_content = f.read().splitlines()[6:]
bgp_content = [item.split() for item in bgp_content]
bgp_prefixes = list(set([item[0] for item in bgp_content]))
bgp_asns = list(set([int(item[1]) for item in bgp_content]))
as_count = len(bgp_asns)
prefix_count = len(bgp_prefixes)
prefix_to_asn = {item[0]: int(item[1]) for item in bgp_content}
tree = SubnetTree.SubnetTree()
for p in bgp_prefixes:
    tree.insert(p)
prefix_to_ancestors = dict()
for p in bgp_prefixes:
    prefix_to_ancestors[p] = list(tree.ancestors(p, 16).keys())
aliased_prefixes_file = args.a

class AliasedPrefix:
    def __init__(self):
        self.aliased_prefixes_tree = SubnetTree.SubnetTree()
        self.fill()

    def fill(self):
        with open(aliased_prefixes_file, "r") as f:
            lines = f.read().splitlines()
            for prefix in tqdm(lines):
                try:
                    self.aliased_prefixes_tree[prefix] = prefix.split("/")[0]
                except ValueError as e:
                    print("Skipped line '" + prefix + "'", file=sys.stderr)

    def search(self, ip):
        try:
            return self.aliased_prefixes_tree[ip]
        except:
            return ip

asndb = pyasn.pyasn(ipasn_file)
aliased_prefix = AliasedPrefix()
coverage_file = args.o
coverage_f = open(args.o, "a")
ips = set()
covered_asns = set()
covered_prefixes = set()
temp_covered_prefixes = set()
router_ips = set()
edges = dict()
topology_dict = dict()
max_gap_dict = defaultdict(int)
packets_num = 0
elapsed_time = 0
with open(args.f, "r") as f:
    lines = f.read().splitlines()
for line in tqdm(lines):
    if line[0] != "#":
        lst = line.split()
        target = lst[0]
        hop = lst[6]
        type_ = int(lst[3])
        ttl = int(lst[5])
        if hop[0] != "2":
            continue
        hop = aliased_prefix.search(hop)
        ips.add(hop)
        if (type_ in [1, 3] and hop != target) or hop.endswith("::1"):
            router_ips.add(hop)
        if target not in topology_dict:
            topology_dict[target] = dict()
        topology_dict[target][ttl] = hop
    else:
        if line.startswith('# Pkts:'):
            packets_num = int(line[8:])
        elif line.startswith('# Elapsed:'):
            elapsed_time = float(line[11:-1])
for target, trace in topology_dict.items():
    trace = sorted(trace.items(), key=lambda x: x[0])
    max_gap = 0
    for i in range(len(trace) - 1):
        src_ttl, src_ip = trace[i]
        dst_ttl, dst_ip = trace[i + 1]
        if src_ip != dst_ip:
            hop_distance = dst_ttl - src_ttl
            max_gap = max(max_gap, hop_distance - 1)
            if (src_ip, dst_ip) not in edges:
                edges[(src_ip, dst_ip)] = hop_distance
            else:
                edges[(src_ip, dst_ip)] = min(edges[(src_ip, dst_ip)], hop_distance)
    max_gap_dict[max_gap] += 1
    target_asn, target_prefix = asndb.lookup(target)
for ip in ips:
    asn, prefix = asndb.lookup(ip)
    if prefix:
        temp_covered_prefixes.add(prefix)
for prefix in temp_covered_prefixes:
    covered_prefixes.update(prefix_to_ancestors[prefix])
for prefix in covered_prefixes:
    covered_asns.add(prefix_to_asn[prefix])
coverage_f.write("%s\n" % args.f)
coverage_f.write("%d\t%d\t%d\t%d\t%d\t%d\t%.2f\n" % (len(ips), len(router_ips), len(edges), len(covered_asns), len(covered_prefixes), packets_num, elapsed_time))
coverage_f.write("%.2f%%\t%.2f%%\t%.2f%%\t%.2f%%\t%.2f%%\n" % (len(ips) / packets_num * 100, len(router_ips) / packets_num * 100, len(edges) / packets_num * 100, len(covered_asns) / as_count * 100, len(covered_prefixes) / prefix_count * 100))
for max_gap, num in sorted(max_gap_dict.items(), key=lambda x: int(x[0]), reverse=True):
    coverage_f.write("%d\t%d\n" % (max_gap, num))
coverage_f.write("\n")
coverage_f.flush()
coverage_f.close()