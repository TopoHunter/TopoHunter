#include "yarrp.h"
#include "ip_ttl_list.h"
#include <sstream>


IPTTLList::IPTTLList() {
    permsize = 0;
    next = 0;
}

IPTTLList::~IPTTLList() {
    targets.clear();
}

void IPTTLList::read(char *in) {
  if (*in == '-') {
    read(std::cin);
  } else {
    std::ifstream ifile(in);
    if (ifile.good() == false)
      fatal("Bad input file: %s", in);
    read(ifile);
  }
}

void IPTTLList::read(std::istream& inlist) {
  std::string line;
  struct in6_addr addr;
  while (getline(inlist, line)) {
    if (!line.empty() && line[line.size() - 1] == '\r')
      line.erase( std::remove(line.begin(), line.end(), '\r'), line.end() );
    
    // 使用istringstream来分割每行数据
    std::istringstream iss(line);
    std::string ipv6Str;
    int number;
    if (!(iss >> ipv6Str >> number)) {
      fatal("Couldn't parse line: %s", line.c_str()); // 或者选择更合适的错误处理方式
      continue;
    }

    if (inet_pton(AF_INET6, ipv6Str.c_str(), &addr) != 1) {
      fatal("Couldn't parse IPv6 address: %s", ipv6Str.c_str());
      continue;
    }

    targets.push_back(std::make_pair(addr, static_cast<uint8_t>(number)));
  }  
  permsize = targets.size();
  debug(LOW, ">> IPv6 targets: " << targets.size());
}


uint32_t IPTTLList::next_address(struct in6_addr *in, uint8_t * ttl) {
  if (next < permsize) {
    *in = targets[next].first;
    *ttl = targets[next].second;
    next = next + 1;
    return 1;
  }
  return 0;
}

uint32_t IPTTLList::next_address(struct in_addr *in, uint8_t * ttl) {
  return 0;
}