import SubnetTree
from collections import defaultdict, deque
import ipaddress
import common
import random
import numpy as np
import json
import time
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

def weighted_random_indices(choices, scores, n, random_prob=0.1):
    try:
        scores = np.array(scores) + 1
        probabilities = scores / scores.sum() * (1 - random_prob) + random_prob / len(scores)
        indices = np.random.choice(len(scores), size=n, replace=True, p=probabilities)
        results = defaultdict(int)
        for indice in indices:
            results[choices[indice]] += 1
        return results
    except Exception as e:
        common.get_logger().error("weight_random_indices error: %s" % e)
        equal_share = n // len(choices)
        remainder = n % len(choices)
        results = defaultdict(int, {choice: equal_share for choice in choices})
        for i in range(remainder):  # Distribute any remainder one by one
            results[choices[i]] += 1
        return results

def generate_first_host(prefix):
    return prefix.split("/")[0] + "1"

def generate_random_ipv6(prefix, count):
    network = ipaddress.IPv6Network(prefix)
    prefix_bits = network.prefixlen
    generated_ips = set()
    for _ in range(count):
        suffix = random.getrandbits(128 - prefix_bits)
        ip_int = int(network.network_address) + suffix
        full_ip = ipaddress.IPv6Address(ip_int)
        generated_ips.add(str(full_ip))
    return generated_ips

def generate_targets(prefix_dict):
    results = set()
    for prefix, num in prefix_dict.items():
        if num > 0:
            results.update(generate_random_ipv6(prefix, num))
    return results

def generate_subprefixes(prefix, subprefix_len):
    network = ipaddress.IPv6Network(prefix)
    subnets = [str(subnet) for subnet in network.subnets(new_prefix=subprefix_len)]
    return set(subnets)

def ipv6_address_to_prefix(ipv6_address, prefix_length):
    try:
        network = ipaddress.IPv6Network((ipv6_address, prefix_length), strict=False)
        return str(network)
    except ValueError as e:
        return None

class Pyasn:
    def __init__(self):
        self.pyasn_tree = SubnetTree.SubnetTree()
        self.bgp_prefixes = set()
        self.fill()
    
    def fill(self):
        with open(common.IPASN_FILE, "r") as f:
            ipasn_content = [line.split() for line in f.read().splitlines() if line[0] != ";"]
            for item in ipasn_content:
                prefix, asn = item[0], int(item[1])
                if int(prefix.split("/")[1]) <= 48:
                    self.pyasn_tree[prefix] = [asn, prefix]
                    self.bgp_prefixes.add(prefix)
        self.pyasn_tree.set_binary_lookup_mode(True)

    def search(self, ip_binary):
        try:
            asn, prefix = self.pyasn_tree[ip_binary[:-1]]
            return asn, prefix
        except:
            return None, None

    def search_all(self, ip_binary):
        try:
            return self.pyasn_tree.search_all(ip_binary[:-1], 16)
        except:
            return []

class TargetValueTree:
    def __init__(self, bgp_prefix, aliased_prefixes, hitlist):
        self.bgp_prefix = bgp_prefix
        self.bgp_prefix_len = int(bgp_prefix.split("/")[1])
        self.probed_times = 0
        self.value = 0
        self.cut = False
        self.aliased_prefixes_tree = SubnetTree.SubnetTree()
        for aliased_prefix in aliased_prefixes:
            self.aliased_prefixes_tree[aliased_prefix] = int(aliased_prefix.split("/")[1])
        self.value_tree = SubnetTree.SubnetTree()
        self.value_tree[self.bgp_prefix] = [int(0), float(0), False]
        self.hitlist_tree = SubnetTree.SubnetTree()
        for ip in hitlist:
            self.hitlist_tree.insert(ip)

    def allocate(self, probe_num):
        target_prefix_dict = defaultdict(int)
        q = deque()
        q.append((self.bgp_prefix, probe_num))
        while q:
            try:
                prefix, num = q.popleft()
                prefix_len = int(prefix.split("/")[1])
                if prefix_len == common.TREE_LEAF_PREFIX_LEN:
                    target_prefix_dict[prefix] += num
                else:
                    try:
                        data = self.value_tree.lookup_exact(prefix)
                    except:
                        data = None
                    if not data or data[1] == 0:
                        target_prefix_dict[prefix] += num
                    else:
                        children = self.value_tree.children(prefix, 16)
                        if len(children) == 0:
                            target_prefix_dict[prefix] += num
                        else:
                            subnets = generate_subprefixes(prefix, (prefix_len // 4 + 1) * 4)
                            unprobed_subnets = subnets - set(children.keys())
                            choices = list(unprobed_subnets)
                            values = [0] * len(unprobed_subnets)
                            for subnet, subnet_data in children.items():
                                if subnet_data[2] == False:
                                    choices.append(subnet)
                                    values.append(subnet_data[1])
                            if len(choices) == 0:
                                target_prefix_dict[prefix] += num
                            else:
                                results = weighted_random_indices(choices, values, num, common.VALUE_TREE_RANDOM)
                                for key, value in results.items():
                                    if key in unprobed_subnets:
                                        target_prefix_dict[key] += value
                                    else:
                                        q.append((key, value))
            except Exception as e:
                common.get_logger().error("TargetValueTree allocate error: %s" % e)
        hitlist_targets = set()
        for prefix, num in sorted(target_prefix_dict.items(), key=lambda x: int(x[0].split("/")[1]), reverse=True):
            try:
                results = self.hitlist_tree.descendant_prefixes(key, 16, num * 10, False, False)
            except:
                results = set()
            if len(results) > num:
                results = set(random.sample(results, num))
            for result in results:
                self.hitlist_tree.remove(result)
            hitlist_targets.update(results)
            target_prefix_dict[prefix] -= len(results)
        return hitlist_targets, generate_targets(target_prefix_dict)

    def update(self, point_dict):
        to_update_dict = defaultdict(list)
        for target_prefix, points in point_dict.items():
            ancestors = self.value_tree.ancestors(target_prefix, 16)
            for ancestor, value in ancestors.items():
                if ancestor not in to_update_dict:
                    to_update_dict[ancestor] = value
                to_update_dict[ancestor][0] += len(points)
                decay_rate = (1 - common.DECAY_RATE * (int(ancestor.split("/")[1]) / common.TREE_LEAF_PREFIX_LEN))
                for point in points:
                    to_update_dict[ancestor][1] *= decay_rate
                    to_update_dict[ancestor][1] += point
            ancestor_max_prefix_length = max([int(prefix.split("/")[1]) for prefix in ancestors.keys()])
            l = (ancestor_max_prefix_length // 4 + 1) * 4
            while l <= common.TREE_LEAF_PREFIX_LEN:
                p = ipv6_address_to_prefix(target_prefix.split("/")[0], l)
                if p not in to_update_dict:
                    to_update_dict[p] = [int(0), float(0), False]
                to_update_dict[p][0] += len(points)
                decay_rate = (1 - common.DECAY_RATE * (l / common.TREE_LEAF_PREFIX_LEN))
                for point in points:
                    to_update_dict[p][1] *= decay_rate
                    to_update_dict[p][1] += point
                l += 4
        for key, value in sorted(to_update_dict.items(), key=lambda x: int(x[0].split("/")[1]), reverse=True):
            need_insert = True
            try:
                if key != self.bgp_prefix and self.aliased_prefixes_tree[key] < int(key.split("/")[1]):
                    need_insert = False
            except:
                pass
            if need_insert:
                self.value_tree[key] = value
                if value[1] < common.CUT_THRESHOLD:
                    if value[0] >= common.CUT_PROBED_TIMES:
                        value[2] = True
                        self.value_tree.remove_subtree(key)
                else:
                    if value[2] == True:
                        value[2] = False
                self.value_tree[key] = value
        data = self.value_tree.lookup_exact(self.bgp_prefix)
        self.probed_times, self.value, self.cut = data[0], data[1], data[2]


class TargetValueForest:
    def __init__(self):
        self.pyasn = Pyasn()
        self.bgp_prefixes = self.pyasn.bgp_prefixes
        self.bgp_prefix_aliased_prefixes = self.divide_aliased_prefixes()
        self.bgp_prefix_first_host, self.warmup_targets, self.bgp_prefix_hitlist = self.process_hitlist()
        self.tree_dict = dict()
        for p in tqdm(self.bgp_prefixes):
            self.tree_dict[p] = TargetValueTree(p, self.bgp_prefix_aliased_prefixes[p], self.bgp_prefix_hitlist[p])

    def divide_aliased_prefixes(self):
        with open(common.ALIASED_PREFIXES_FILE, "r") as f:
            aliased_prefixes = f.read().splitlines()
        bgp_prefix_aliased_prefixes = defaultdict(set)
        for p in tqdm(aliased_prefixes):
            if int(p.split("/")[1]) <= common.TREE_LEAF_PREFIX_LEN:
                for p_asn, p_prefix in self.pyasn.search_all(convert_ipv6_to_binary(p)):
                    bgp_prefix_aliased_prefixes[p_prefix].add(p)
        return bgp_prefix_aliased_prefixes

    def process_hitlist(self):
        bgp_prefix_first_host = list(set([generate_first_host(p) for p in self.bgp_prefixes]))
        random.shuffle(bgp_prefix_first_host)
        bgp_prefix_first_host = deque(bgp_prefix_first_host)
        with open(common.HITLIST_Z48_FILE, "r") as f:
            warmup_targets = f.read().splitlines()
        random.shuffle(warmup_targets)
        warmup_targets = deque(warmup_targets)
        bgp_prefix_hitlist = defaultdict(set)
        with open(common.HITLIST_Z64_FILE, "r") as f:
            hitlist_z64 = f.read().splitlines()
        for ip in tqdm(hitlist_z64):
            ip_binary = convert_ipv6_to_binary(ip)
            ip_asn, ip_prefix = self.pyasn.search(ip_binary)
            if ip_prefix:
                bgp_prefix_hitlist[ip_prefix].add(ip)
        return bgp_prefix_first_host, warmup_targets, bgp_prefix_hitlist

    def allocate(self):
        if len(self.bgp_prefix_first_host) > 0:
            targets = set()
            for _ in range(min(common.TARGETS_NUM_PER_OPR, len(self.bgp_prefix_first_host))):
                targets.add(self.bgp_prefix_first_host.popleft())
            return 0, targets, set()
        elif len(self.warmup_targets) > 0:
            targets = set()
            for _ in range(min(common.TARGETS_NUM_PER_OPR, len(self.warmup_targets))):
                targets.add(self.warmup_targets.popleft())
            return 1, targets, set()
        else:
            total_hitlist_targets, total_generated_targets = set(), set()
            choices = [p for p in self.bgp_prefixes if self.tree_dict[p].cut == False]
            values = [self.tree_dict[p].value for p in self.bgp_prefixes if self.tree_dict[p].cut == False]
            if len(choices) == 0:
                choices = [p for p in self.bgp_prefixes]
                values = [self.tree_dict[p].value for p in self.bgp_prefixes]
            probe_num_dict = weighted_random_indices(choices, values, common.TARGETS_NUM_PER_OPR, common.VALUE_TREE_RANDOM)
            for prefix, probe_num in probe_num_dict.items():
                hitlist_targets, generated_targets = self.tree_dict[prefix].allocate(probe_num)
                total_hitlist_targets.update(hitlist_targets)
                total_generated_targets.update(generated_targets)
            return 2, total_hitlist_targets, total_generated_targets

    def update(self, point_dict):
        # key: target_binary, value: point
        bgp_prefix_point_dict = dict()
        for target_binary, point in point_dict.items():
            target_asn, target_bgp_prefix = self.pyasn.search(target_binary)
            if target_bgp_prefix:
                if target_bgp_prefix not in bgp_prefix_point_dict:
                    bgp_prefix_point_dict[target_bgp_prefix] = dict()
                target_prefix = str(ipaddress.IPv6Network((target_binary[:-1], common.TREE_LEAF_PREFIX_LEN), strict=False))
                if target_prefix not in bgp_prefix_point_dict[target_bgp_prefix]:
                    bgp_prefix_point_dict[target_bgp_prefix][target_prefix] = list()
                bgp_prefix_point_dict[target_bgp_prefix][target_prefix].append(point)
        for bgp_prefix in bgp_prefix_point_dict.keys():
            self.tree_dict[bgp_prefix].update(bgp_prefix_point_dict[bgp_prefix])