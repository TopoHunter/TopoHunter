#include "target_control_state.h"
#include "ip_ttl_list.h"
#include "sqlite.h"

typedef std::pair<std::string, bool> val_t;
typedef std::map<std::string, val_t> params_t;

class YarrpConfig {
  public:
  YarrpConfig() : rate(10), random_scan(true), ttl_neighborhood(0),
    testing(false), entire(false), output(NULL), 
    bgpfile(NULL), inlist(NULL), blocklist(NULL),
    count(0), minttl(1), maxttl(16), seed(0),
    dstport(80),
    ipv6(false), int_name(NULL), dstmac(NULL), srcmac(NULL), 
    coarse(false), fillmode(32), poisson(0),
    probesrc(NULL), probe(true), receive(true), instance(0), v6_eh(255), out(NULL),
    yarrp_id(0x79727036), inlist2(NULL), inlist3(NULL), maxanonymous(5), loopbackdetect(true), reachdetect(true),
    target_control_state_dict(NULL), database(NULL), ip_ttl_list(NULL), sqlite_path(NULL), record(NULL), record_out(NULL), validSecs(30) {};

  ~YarrpConfig() {
    if (target_control_state_dict) {
      delete target_control_state_dict;
    }
    if (database) {
      delete database;
    }
    if (record_out) {
      fclose(record_out);
    }
  }

  void parse_opts(int argc, char **argv); 
  void usage(char *prog);
  void set(std::string, std::string, bool);
  void dump() { if (output) dump(out); }
  unsigned int rate;
  bool random_scan;
  uint8_t ttl_neighborhood;
  bool testing; 
  bool entire;  /* speed as sole emphasis, to scan entire Internet */
  char *output;
  char *bgpfile;
  char *inlist;
  char *inlist2;
  char *inlist3;
  char *blocklist;
  uint32_t count;
  uint8_t minttl;
  uint8_t maxttl;
  int maxanonymous;
  uint32_t seed;
  uint16_t dstport;
  bool ipv6;
  char *int_name;
  uint8_t *dstmac;
  uint8_t *srcmac;
  int type;
  bool coarse;
  int fillmode;
  int poisson;
  char *probesrc;
  bool probe;
  bool receive;
  uint8_t instance;
  uint8_t v6_eh;
  uint8_t granularity;
  FILE *out;   /* output file stream */
  params_t params;
  char *pcap;
  char *exception;
  char *record;
  FILE *record_out;
  uint32_t yarrp_id; 
  TargetControlStateDict *target_control_state_dict;
  NodeDatabase *database;
  IPTTLList *ip_ttl_list;
  char *sqlite_path;
  bool loopbackdetect;
  bool reachdetect;
  uint32_t validSecs;

  private:
  void dump(FILE *fd);
};
