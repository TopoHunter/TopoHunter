#ifndef TARGET_CONTROL_STATE_H
#define TARGET_CONTROL_STATE_H


#include <string>
#include <unordered_map>
#include <stdint.h>
#include <pthread.h>
#include <vector>
#include <fstream>
#include "libcperm/cperm.h"
#include <deque>
#include <algorithm> // For std::find

#define FIXED_QUEUE_MAX_SIZE 3


struct in6_addr_equal {
    bool operator()(const struct in6_addr& lhs, const struct in6_addr& rhs) const {
        return memcmp(lhs.s6_addr, rhs.s6_addr, 16) == 0;
    }
};


struct in6_addr_hash {
    std::size_t operator()(const struct in6_addr& addr) const {
        std::size_t hash = 0;
        for (int i = 0; i < 4; ++i) {
            hash ^= addr.s6_addr32[i] + 0x9e3779b9 + (hash << 6) + (hash >> 2);
        }
        return hash;
    }
};


class FixedQueue {
private:
    std::deque<std::size_t> deque;

public:
    FixedQueue() {}

    void push(const struct in6_addr* value) {
        if (deque.size() == FIXED_QUEUE_MAX_SIZE) {
            deque.pop_front(); // Remove the oldest element
        }
        in6_addr_hash hasher;
        deque.push_back(hasher(*value)); // Insert new element
    }

    bool contains(const struct in6_addr* value) const {
        in6_addr_hash hasher;
        return std::find(deque.begin(), deque.end(), hasher(*value)) != deque.end();
    }

    bool empty() const {
        return deque.empty();
    }

    size_t size() const {
        return deque.size();
    }
};


struct TargetControlState {
    uint8_t splitTTL;
    uint8_t forwardProbedTTL;
    uint8_t backwardProbedTTL;
    bool nextProbeDirection;
    uint8_t farthest_received_forward_ttl;
    bool forwardComplete;
    bool backwardComplete;
    FixedQueue fixed_queue;
};


class TargetControlStateDict {
    public:
    std::unordered_map<struct in6_addr, TargetControlState, in6_addr_hash, in6_addr_equal> dict;
    std::vector<struct in6_addr> targets;

    TargetControlStateDict(uint8_t _minttl, uint8_t _maxttl, bool _rand, int _maxanonymous, FILE* _record_out);
    ~TargetControlStateDict();
    void read(char *in);
    void read(std::istream& inlist);
    uint32_t next_address(struct in6_addr *in, uint8_t * ttl);
    uint32_t next_address(struct in_addr *in, uint8_t * ttl);
    uint32_t count() { return dict.size() * (maxttl - minttl + 1); }

    protected:
    uint8_t minttl;
    uint8_t maxttl;
    uint8_t ttlbits;
    uint32_t ttlmask;
    uint32_t ttlprefix;
    bool rand;
    int maxanonymous;
    FILE* record_out;
};

#endif 