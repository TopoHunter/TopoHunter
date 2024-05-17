from SubnetTree import SubnetTree
from collections import defaultdict, deque
import pyasn
import ipaddress
import common
import random
import numpy as np
import json
import time

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
        for i in range(remainder):
            results[choices[i]] += 1
        return results

def generate_loopback_ipv6(prefix):
    return prefix.split("/")[0] + "1"

def generate_random_ipv6(prefix, count):
    network = ipaddress.IPv6Network(prefix)
    prefix_bits = network.prefixlen
    assert prefix_bits <= 64, "target prefix len must be <= 64"

    generated_ips = set()
    for _ in range(count):
        random_middle = random.getrandbits(64 - prefix_bits)
        if random.random() < 0.5:
            iid = random.getrandbits(8)
        else:
            iid = random.getrandbits(64)
        ip_int = int(network.network_address) + (random_middle << 64) + iid
        full_ip = ipaddress.IPv6Address(ip_int)
        generated_ips.add(str(full_ip))
    return generated_ips

def generate_targets(prefix_dict):
    results = set()
    for prefix, num in prefix_dict.items():
        results.update(generate_random_ipv6(prefix, num))
    return results

def generate_subprefixes(prefix, subprefix_len):
    network = ipaddress.IPv6Network(prefix)
    subnets = [str(subnet) for subnet in network.subnets(new_prefix=subprefix_len)]
    return set(subnets)

def ipv6_address_to_prefix(ipv6_address, prefix_length):
    try:
        ip_address = ipaddress.IPv6Address(ipv6_address)
        network = ipaddress.IPv6Network((ip_address, prefix_length), strict=False)
        return str(network)
    except ValueError as e:
        return None

class TargetValueTree:
    def __init__(self, bgp_prefix, aliased_tree):
        self.bgp_prefix = bgp_prefix
        self.bgp_prefix_len = int(bgp_prefix.split("/")[1])
        self.aliased_tree = aliased_tree
        self.value_tree = SubnetTree()
        self.seed_addr_tree = SubnetTree()
        self.probed_times = 0
        self.value = 0
        self.cut = False
        self.num_seed_addr = 0
        self.value_tree[self.bgp_prefix] = [int(0), float(0), False]

    def insert_seed_prefixes(self, seed_prefixes):
        for prefix in seed_prefixes:
            self.seed_addr_tree.insert(prefix)
        self.num_seed_addr += len(seed_prefixes)

    def allocate(self, probe_num):
        result_dict = defaultdict(int)
        q = deque()
        q.append((self.bgp_prefix, probe_num))
        while q:
            try:
                prefix, num = q.popleft()
                prefix_len = int(prefix.split("/")[1])
                if prefix_len == common.TREE_LEAF_PREFIX_LEN:
                    result_dict[prefix] += num
                else:
                    try:
                        data = self.value_tree.lookup_exact(prefix)
                    except:
                        data = None
                    if not data or data[1] == 0:
                        result_dict[prefix] += num
                    else:
                        children = self.value_tree.children(prefix, 16)
                        if len(children) == 0:
                            result_dict[prefix] += num
                        else:
                            subprefix_len = (prefix_len // 4 + 1) * 4
                            subnets = generate_subprefixes(prefix, subprefix_len)
                            unprobed_subnets = subnets - set(children.keys())
                            choices = list(unprobed_subnets)
                            scores = [0] * len(unprobed_subnets)
                            for key, value in children.items():
                                if value[2] == False:
                                    choices.append(key)
                                    scores.append(value[1])
                            if len(choices) == 0:
                                result_dict[prefix] += num
                            else:
                                results = weighted_random_indices(choices, scores, num, common.VALUE_TREE_RANDOM)
                                for key, value in results.items():
                                    if key in unprobed_subnets:
                                        result_dict[key] += value
                                    else:
                                        q.append((key, value))
            except Exception as e:
                common.get_logger().error("TargetValueTree allocate error: %s" % e)

        target_prefix_dict = defaultdict(int)
        seed_targets = set()
        for key, value in sorted(result_dict.items(), key=lambda x: int(x[0].split("/")[1]), reverse=True):
            try:
                results = self.seed_addr_tree.descendant_prefixes(key, 16, value, False, False)
            except:
                results = set()
            for result in results:
                self.seed_addr_tree.remove(result)
            seed_targets.update(results)
            if len(results) < value:
                target_prefix_dict[key] += value - len(results)

        self.num_seed_addr -= len(seed_targets)
        return seed_targets, generate_targets(target_prefix_dict)

    def update(self, point_dict):
        to_update_dict = defaultdict(list)
        for target, point_dict in point_dict.items():
            ancestors = self.value_tree.ancestors(target, 16)
            for ancestor, value in ancestors.items():
                if ancestor not in to_update_dict:
                    to_update_dict[ancestor] = value
                to_update_dict[ancestor][0] += len(point_dict)
                decay_rate = (1 - common.DECAY_RATE * (int(ancestor.split("/")[1]) / common.TREE_LEAF_PREFIX_LEN))
                for point in point_dict.values():
                    to_update_dict[ancestor][1] *= decay_rate
                    to_update_dict[ancestor][1] += point
            ancestor_max_prefix_length = max([int(prefix.split("/")[1]) for prefix in ancestors.keys()])
            l = (ancestor_max_prefix_length // 4 + 1) * 4
            while l <= common.TREE_LEAF_PREFIX_LEN:
                p = ipv6_address_to_prefix(target.split("/")[0], l)
                if p not in to_update_dict:
                    to_update_dict[p] = [int(0), float(0), False]
                to_update_dict[p][0] += len(point_dict)
                decay_rate = (1 - common.DECAY_RATE * (l / common.TREE_LEAF_PREFIX_LEN))
                for point in point_dict.values():
                    to_update_dict[p][1] *= decay_rate
                    to_update_dict[p][1] += point
                l += 4
        for key, value in sorted(to_update_dict.items(), key=lambda x: int(x[0].split("/")[1]), reverse=True):
            need_insert = True
            try:
                if key != self.bgp_prefix and self.aliased_tree[key] < int(key.split("/")[1]):
                    need_insert = False
            except:
                pass
            if need_insert:
                self.value_tree[key] = value
                if value[1] < 0.1:
                    if value[0] >= common.CUT_PROBED_TIMES:
                        value[2] = True
                        self.value_tree.remove_subtree(key)
                else:
                    if value[2] == True:
                        value[2] = False
                self.value_tree[key] = value
        data = self.value_tree.lookup_exact(self.bgp_prefix)
        self.probed_times, self.value, self.cut = data[0], data[1], data[2]
        
    def write(self, prefix, level=2):
        if level == 0:
            return []
            
        try:
            children = self.value_tree.children(prefix, 16)
        except:
            children = dict()
        if len(children) == 0:
            return []

        results = []
        for child_prefix, child_data in children.items():
            results.append({"prefix": child_prefix, "probed_times": child_data[0], "value": child_data[1], "cut": child_data[2], "children": self.write(child_prefix, level - 1)})
        results.sort(key=lambda x: (x["value"], x["probed_times"]), reverse=True)
        return results


class TargetValueForest:
    def __init__(self, warmup_targets):
        with open(common.IPASN_FILE, "r") as f:
            content = f.read().splitlines()[6:]
        with open(common.ALIASED_FILE, "r") as f:
            aliased_prefixes = set(f.read().splitlines())
        self.aliased_tree = SubnetTree()
        for p in aliased_prefixes:
            if int(p.split("/")[1]) <= common.TREE_LEAF_PREFIX_LEN:
                self.aliased_tree[p] = int(p.split("/")[1])
        self.bgp_prefixes = [item.split()[0] for item in content]
        self.asndb = pyasn.pyasn(common.IPASN_FILE)
        self.tree_dict = dict()
        for p in self.bgp_prefixes:
            self.tree_dict[p] = TargetValueTree(p, self.aliased_tree)
        with open(common.SEED_PREFIXES_FILE, "r") as f:
            seed_prefixes = f.read().splitlines()
        seed_prefix_dict = defaultdict(set)
        seed_prefix_z48 = set()
        for p in seed_prefixes:
            bgp_asn, bgp_prefix = self.asndb.lookup(p.split("/")[0])
            if bgp_prefix:
                seed_prefix_dict[bgp_prefix].add(p)
        self.warmup_targets = list(warmup_targets)
        random.shuffle(self.warmup_targets)
        self.warmup_targets = deque(self.warmup_targets)
        common.get_logger().info("warmup targets num: %d, warmup rounds: %d" % (len(self.warmup_targets), len(self.warmup_targets) // common.TARGETS_NUM_PER_OPR))
        # probing stage: 0 warmup 1 feedback
        self.probing_stage = 0
        for bgp_prefix, prefixes in seed_prefix_dict.items():
            self.tree_dict[bgp_prefix].insert_seed_prefixes(prefixes)

    def allocate(self, probe_num):
        try:
            total_seed_targets = set()
            total_generated_targets = set()
            choices = [p for p in self.bgp_prefixes if self.tree_dict[p].cut == False]
            scores = [self.tree_dict[p].value for p in self.bgp_prefixes if self.tree_dict[p].cut == False]
            if len(choices) == 0:
                choices = [p for p in self.bgp_prefixes]
                scores = [self.tree_dict[p].value for p in self.bgp_prefixes]
                common.get_logger().info("all tree cut, use the whole forest")
            probe_num_dict = weighted_random_indices(choices, scores, probe_num, common.VALUE_TREE_RANDOM)
            for prefix, num in probe_num_dict.items():
                try:
                    seed_targets, generated_targets = self.tree_dict[prefix].allocate(num)
                    total_seed_targets.update(seed_targets)
                    total_generated_targets.update(generated_targets)
                except Exception as e:
                    common.get_logger().error("TargetValueForest allocate: %s" % e)
            return total_seed_targets, total_generated_targets
        except Exception as e:
            common.get_logger().error("TargetValueForest allocate: %s" % e)
            return set(), set()

    def warmup_allocate(self):
        if len(self.warmup_targets) >= 2 * common.TARGETS_NUM_PER_OPR:
            num = common.TARGETS_NUM_PER_OPR
        else:
            num = len(self.warmup_targets)
            self.probing_stage = 1
        targets = set([self.warmup_targets.popleft() for _ in range(num)])
        return targets

    def update(self, point_dict):
        try:
            bgp_prefix_point_dict = dict()
            for target_prefix, point in point_dict.items():
                bgp_asn, bgp_prefix = self.asndb.lookup(target_prefix.split("/")[0])
                if bgp_prefix:
                    if bgp_prefix not in bgp_prefix_point_dict:
                        bgp_prefix_point_dict[bgp_prefix] = dict()
                    bgp_prefix_point_dict[bgp_prefix][target_prefix] = point
            for bgp_prefix, value in bgp_prefix_point_dict.items():
                try:
                    self.tree_dict[bgp_prefix].update(value)
                except Exception as e:
                    common.get_logger().error("TargetValueForest error %s" % e)
        except Exception as e:
            common.get_logger().error("TargetValueForest error %s" % e)

    def write(self, file_path):
        value_forest_info = []
        for prefix in self.bgp_prefixes:
            value_tree_info = {"prefix": prefix, "probed_times": 0, "value": 0, "cut": False, "value_tree_size": 0, "num_seed_addr": 0, "children": []}
            value_tree = self.tree_dict[prefix]
            value_tree_info["probed_times"] = value_tree.probed_times
            value_tree_info["value"] = value_tree.value
            value_tree_info["cut"] = value_tree.cut
            value_tree_info["value_tree_size"] = value_tree.value_tree.num_active_node()
            value_tree_info["num_seed_addr"] = value_tree.num_seed_addr
            value_tree_info["children"] = value_tree.write(prefix, level=2)
            value_forest_info.append(value_tree_info)
        value_forest_info.sort(key=lambda x: x["value"], reverse=True)
        with open(file_path, "w") as f:
            json.dump(value_forest_info, f, indent=2)
