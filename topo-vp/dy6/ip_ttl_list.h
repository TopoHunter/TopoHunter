#ifndef IP_TTL_LIST_H
#define IP_TTL_LIST_H


#include <string>
#include <vector>
#include <utility>

class IPTTLList {
    public:
    IPTTLList();
    ~IPTTLList();
    std::vector<std::pair<struct in6_addr, uint8_t>> targets;
    void read(char *in);
    void read(std::istream& inlist);
    uint32_t count() { return permsize; }
    uint32_t next_address(struct in6_addr *in, uint8_t * ttl);
    uint32_t next_address(struct in_addr *in, uint8_t * ttl);

    protected:
    uint64_t permsize;
    uint64_t next;
};


#endif