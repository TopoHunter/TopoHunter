#include "yarrp.h"
#include "target_control_state.h"
#include <sstream>
#include <cstdlib>
#include <random>


TargetControlStateDict::TargetControlStateDict(uint8_t _minttl, uint8_t _maxttl, bool _rand, int _maxanonymous, FILE* _record_out) {
  minttl = _minttl;
  maxttl = _maxttl;
  ttlbits = intlog(maxttl);
  ttlmask = 0xffffffff >> (32 - ttlbits);
  ttlprefix = ttlmask ^ 0xff;
  rand = _rand;
  maxanonymous = _maxanonymous;
  record_out = _record_out;
}


TargetControlStateDict::~TargetControlStateDict() {
  targets.clear();
  dict.clear();
  record_out = NULL;
}


void TargetControlStateDict::read(char *in) {
  if (*in == '-') {
    read(std::cin);
  } else {
    std::ifstream ifile(in);
    if (ifile.good() == false)
      fatal("Bad input file: %s", in);
    read(ifile);
  }
}


void TargetControlStateDict::read(std::istream& inlist) {
  std::string line;
  struct in6_addr addr;
  std::random_device rd;
  std::mt19937 gen(rd());
  std::bernoulli_distribution d(0.5);
  while (getline(inlist, line)) {
    if (!line.empty() && line[line.size() - 1] == '\r')
      line.erase( std::remove(line.begin(), line.end(), '\r'), line.end() );
    
    std::istringstream iss(line);
    std::string ipv6Str;
    int number;
    if (!(iss >> ipv6Str >> number)) {
      fatal("Couldn't parse line: %s", line.c_str());
      continue;
    }

    if (inet_pton(AF_INET6, ipv6Str.c_str(), &addr) != 1) {
      fatal("Couldn't parse IPv6 address: %s", ipv6Str.c_str());
      continue;
    }

    targets.push_back(addr);
    dict[addr] = TargetControlState{static_cast<uint8_t>(number), static_cast<uint8_t>(number), static_cast<uint8_t>(number + 1), d(gen), static_cast<uint8_t>(number), false, false};
  }  
  debug(LOW, ">> IPv6 targets: " << dict.size());
}


uint32_t TargetControlStateDict::next_address(struct in6_addr *in, uint8_t * ttl) {
  char str_addr[INET6_ADDRSTRLEN];
  while (true) {
    if (targets.size() == 0)
      return 0;
    int index = std::rand() % targets.size();
    *in = targets[index];
    auto it = dict.find(*in);
    if (it != dict.end()) {
      if ((it->second.forwardComplete) && (it->second.backwardComplete)) {
        targets[index] = targets.back();
        targets.pop_back();
        inet_ntop(AF_INET6, in, str_addr, sizeof(str_addr));
        fprintf(record_out, "%s\t%u\t%u\t%u\n", str_addr, it->second.splitTTL, it->second.backwardProbedTTL, it->second.forwardProbedTTL);
        continue;
      }
      if (it->second.nextProbeDirection) {
        if (it->second.forwardComplete) {
          it->second.nextProbeDirection = false;
          continue;
        }
        if (maxanonymous != -1) {
          if (it->second.forwardProbedTTL + 1 - it->second.farthest_received_forward_ttl > maxanonymous) {
            it->second.forwardComplete = true;
            continue;
          }
        }
        it->second.forwardProbedTTL++;
        *ttl = it->second.forwardProbedTTL;
        if (*ttl == maxttl)
          it->second.forwardComplete = true;
        if (!it->second.backwardComplete)
          it->second.nextProbeDirection = false;
        return 1;
      } else {
        if (it->second.backwardComplete) {
          it->second.nextProbeDirection = true;
          continue;
        }
        it->second.backwardProbedTTL--;
        *ttl = it->second.backwardProbedTTL;
        if (*ttl == minttl)
          it->second.backwardComplete = true;
        if (!it->second.forwardComplete)
          it->second.nextProbeDirection = true;
        return 1;
      }
    }
  }
}

uint32_t TargetControlStateDict::next_address(struct in_addr *in, uint8_t * ttl) {
  return 0;
}