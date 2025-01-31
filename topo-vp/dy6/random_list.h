/****************************************************************************
   Program:     $Id: $
   Date:        $Date: $
   Description: random subnet list 
****************************************************************************/

#ifndef RANDOM_LIST_H
#define RANDOM_LIST_H


#include <stdint.h>
#include <pthread.h>
#include <vector>
#include <fstream>
#include "libcperm/cperm.h"

#include "subnet_list.h"

using namespace std;

class RandomSubnetList : public SubnetList {
  public:
  RandomSubnetList(uint8_t _maxttl, uint8_t _gran);
  ~RandomSubnetList();

  uint32_t rand(uint32_t min, uint32_t max);
  void seed();
  virtual uint32_t next_address(struct in_addr *in, uint8_t *ttl);
  virtual uint32_t next_address(struct in6_addr *in, uint8_t *ttl);

  private:
  uint16_t getHost(uint8_t *addr);
  uint64_t rndIID(uint32_t *addr);
  uint8_t key[32];
  bool seeded;
  cperm_t* perm;
};

class IPList {
  public:
  IPList(uint8_t _minttl, uint8_t _maxttl, bool _rand, bool _entire);
  virtual ~IPList() {};
  virtual uint32_t next_address(struct in_addr *in, uint8_t * ttl) = 0;
  virtual uint32_t next_address(struct in6_addr *in, uint8_t * ttl) = 0;
  virtual void seed() = 0;
  void read(char *in);
  virtual void read(std::istream& in) = 0;
  uint32_t count() { return permsize; }
  void setkey(int seed);

  protected:
  uint8_t log2(uint8_t x);
  uint8_t key[KEYLEN];
  cperm_t* perm;
  uint64_t permsize;
  uint8_t minttl;
  uint8_t maxttl;
  uint8_t ttlbits;
  uint32_t ttlmask;
  uint32_t ttlprefix;
  bool rand;
  bool entire;
  bool seeded;
};

class IPList4 : public IPList {
  public:
  IPList4(uint8_t _minttl, uint8_t _maxttl, bool _rand, bool _entire) : IPList(_minttl, _maxttl, _rand, _entire) {};
  virtual ~IPList4();
  uint32_t next_address(struct in_addr *in, uint8_t * ttl);
  uint32_t next_address_seq(struct in_addr *in, uint8_t * ttl);
  uint32_t next_address_rand(struct in_addr *in, uint8_t * ttl);
  uint32_t next_address_entire(struct in_addr *in, uint8_t * ttl);
  uint32_t next_address(struct in6_addr *in, uint8_t * ttl) { return 0; };
  void read(std::istream& in);
  void seed();

  private:
  std::vector<uint32_t> targets;
};

class IPList6 : public IPList {
  public:
  IPList6(uint8_t _minttl, uint8_t _maxttl, bool _rand, bool _entire) : IPList(_minttl, _maxttl, _rand, _entire) {};
  virtual ~IPList6();
  uint32_t next_address(struct in6_addr *in, uint8_t * ttl);
  uint32_t next_address_seq(struct in6_addr *in, uint8_t * ttl);
  uint32_t next_address_rand(struct in6_addr *in, uint8_t * ttl);
  uint32_t next_address_entire(struct in6_addr *in, uint8_t * ttl);
  uint32_t next_address(struct in_addr *in, uint8_t * ttl) { return 0; };
  void read(std::istream& in);
  void seed();

  private:
  std::vector<struct in6_addr> targets;
};

#endif /* RANDOM_LIST_H */
