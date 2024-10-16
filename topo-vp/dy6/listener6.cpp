/****************************************************************************
   Program:     $Id: listener.cpp 40 2016-01-02 18:54:39Z rbeverly $
   Date:        $Date: 2016-01-02 10:54:39 -0800 (Sat, 02 Jan 2016) $
   Description: yarrp listener thread
****************************************************************************/
#include "yarrp.h"
#include <signal.h>

static volatile bool run = true;
void intHandler(int dummy);

bool operator==(const struct in6_addr& a, const struct in6_addr& b) {
    return memcmp(&a, &b, sizeof(struct in6_addr)) == 0;
}

#ifndef _LINUX
int bpfinit(char *dev, size_t *bpflen) {
    int rcvsock = -1;

    debug(DEVELOP, ">> Listener6 BPF");
    rcvsock = bpfget();
    if (rcvsock < 0) fatal("bpf open error\n");
    struct ifreq bound_if;
    strcpy(bound_if.ifr_name, dev);
    if (ioctl(rcvsock, BIOCSETIF, &bound_if) > 0) fatal("ioctl err\n");
    uint32_t enable = 1;
    if (ioctl(rcvsock, BIOCSHDRCMPLT, &enable) <0) fatal("ioctl err\n");
    if (ioctl(rcvsock, BIOCIMMEDIATE, &enable) <0) fatal("ioctl err\n");
    struct bpf_program fcode = {0};
    struct bpf_insn insns[] = {
        BPF_STMT(BPF_LD+BPF_H+BPF_ABS, 12),
        BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, ETHERTYPE_IPV6, 0, 3),
        BPF_STMT(BPF_LD+BPF_B+BPF_ABS, 20),
        BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, IPPROTO_ICMPV6, 0, 1),
        BPF_STMT(BPF_RET+BPF_K, (u_int)-1),
        BPF_STMT(BPF_RET+BPF_K, 0),
    };
    fcode.bf_len = sizeof(insns) / sizeof(struct bpf_insn);
    fcode.bf_insns = &insns[0];
    if(ioctl(rcvsock, BIOCSETF, &fcode) < 0) fatal("set filter\n");
    ioctl(rcvsock, BIOCGBLEN, bpflen);
    return rcvsock;
}
#endif

void *listener6(void *args) {
    fd_set rfds;
    Traceroute6 *trace = reinterpret_cast < Traceroute6 * >(args);
    pcap_t *pcap_handle = NULL;
    pcap_dumper_t *pcap_dumper = NULL;
    FILE *pcap_file = NULL;
    struct pcap_pkthdr pcap_hdr;
    struct timeval current_time;
    // If pcap is not empty
    if (trace->config->pcap) {
        // Open file for writing
        pcap_file = fopen(trace->config->pcap, "wb");
        // Creates a pcap file and opens it for writing
        pcap_handle = pcap_open_dead(DLT_EN10MB, 65535);
        // Open a pcap file for writing
        pcap_dumper = pcap_dump_fopen(pcap_handle, pcap_file);
    }
    pcap_t *exception_handle = NULL;
    pcap_dumper_t *exception_dumper = NULL;
    FILE *exception_file = NULL;
    // If exception is not empty
    if (trace->config->exception) {
        // Open file for writing
        exception_file = fopen(trace->config->exception, "wb");
        exception_handle = pcap_open_dead(DLT_EN10MB, 65535);
        exception_dumper = pcap_dump_fopen(exception_handle, exception_file);
    }
    struct timeval timeout;
    unsigned char *buf = (unsigned char *) calloc(1,PKTSIZE);
    uint32_t nullreads = 0;
    int n, len;
    TTLHisto *ttlhisto = NULL;
    uint32_t elapsed = 0;
    struct ip6_hdr *ip = NULL;                /* IPv6 hdr */
    struct icmp6_hdr *ippayload = NULL;       /* ICMP6 hdr */
    int rcvsock;                              /* receive (icmp) socket file descriptor */

    /* block until main thread says we're ready. */
    trace->lock(); 
    trace->unlock(); 

#ifdef _LINUX
    if ((rcvsock = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0) {
        cerr << "yarrp listener socket error:" << strerror(errno) << endl;
    }

    /* bind PF_PACKET to single interface */
    struct ifreq ifr;
    strncpy(ifr.ifr_name, trace->config->int_name, IFNAMSIZ);
    if (ioctl(rcvsock, SIOCGIFINDEX, &ifr) < 0) fatal ("ioctl err");;
    struct sockaddr_ll sll;
    memset(&sll, 0, sizeof(sll));
    sll.sll_family = PF_PACKET;
    sll.sll_protocol = htons(ETH_P_ALL);
    sll.sll_ifindex = ifr.ifr_ifindex;
    if (bind(rcvsock, (struct sockaddr*) &sll, sizeof(sll)) < 0) {
        fatal("Bind to PF_PACKET socket");
    }
#else
    /* Init BPF */
    size_t blen = 0;
    rcvsock = bpfinit(trace->config->int_name, &blen);
    unsigned char *bpfbuf = (unsigned char *) calloc(1,blen);
    struct bpf_hdr *bh = NULL;
#endif

    signal(SIGINT, intHandler);
    while (true and run) {
        if (trace->stop)
            break;
        if (nullreads >= MAXNULLREADS)
            break;
#ifdef _LINUX
        timeout.tv_sec = 5;
        timeout.tv_usec = 0;
        FD_ZERO(&rfds);
        FD_SET(rcvsock, &rfds);
        n = select(rcvsock + 1, &rfds, NULL, NULL, &timeout);
        if (n == 0) {
            nullreads++;
            cerr << ">> Listener: timeout " << nullreads;
            cerr << "/" << MAXNULLREADS << endl;
            continue;
        }
	if (n == -1) {
            fatal("select error");
        }
        nullreads = 0;
        len = recv(rcvsock, buf, PKTSIZE, 0); 
#else
        len = read(rcvsock, bpfbuf, blen);
	unsigned char *p = bpfbuf;
reloop:
        bh = (struct bpf_hdr *)p;
	buf = p + bh->bh_hdrlen;  /* realign buf */
#endif
        if (len == -1) {
            fatal("%s %s", __func__, strerror(errno));
        }
        gettimeofday(&current_time, NULL);
        ip = (struct ip6_hdr *)(buf + ETH_HDRLEN);
        if ((ip->ip6_nxt == IPPROTO_ICMPV6) and (ip->ip6_dst == trace->getSource()->sin6_addr)) {
            ippayload = (struct icmp6_hdr *)&buf[ETH_HDRLEN + sizeof(struct ip6_hdr)];
            elapsed = trace->elapsed();
            if ( (ippayload->icmp6_type == ICMP6_TIME_EXCEEDED) or
                 (ippayload->icmp6_type == ICMP6_DST_UNREACH) or
                 (ippayload->icmp6_type == ICMP6_ECHO_REPLY) ) {
                ICMP6 *icmp = new ICMP6(ip, ippayload, elapsed, trace->config->coarse, trace->config->yarrp_id);
                if (icmp->is_yarrp) {
                    if (pcap_dumper) {
                        memset(&pcap_hdr, 0, sizeof(pcap_hdr));
                        pcap_hdr.ts = current_time;
                        pcap_hdr.caplen = len;
                        pcap_hdr.len = len;
                        pcap_dump((u_char *)pcap_dumper, &pcap_hdr, buf);
                        pcap_dump_flush(pcap_dumper);
                    }
                    if (verbosity > LOW)
                        icmp->print();
                    if (trace->config->target_control_state_dict) {
                        // forwardComplete is true if an echo reply or unreachable packet is received
                        if ((icmp->getType() == 129) or (icmp->getType() == 1) or ((icmp->getType() == 3) and (icmp->true_target == *(icmp->getSrc6())))) {
                            if (trace->config->reachdetect) {
                                auto it = trace->config->target_control_state_dict->dict.find(icmp->true_target);
                                if (it != trace->config->target_control_state_dict->dict.end()) {
                                    it->second.forwardComplete = true;
                                }
                            }
                        }
                        // Otherwise, if other types of packets are received (typically time exceeded)
                        // If an already probed interface is received, backwardComplete is true
                        // Otherwise, insert the database
                        // If a loopback is encountered, forwardComplete is also set to true
                        else {
                            auto it = trace->config->target_control_state_dict->dict.find(icmp->true_target);
                            if (it != trace->config->target_control_state_dict->dict.end()) {
                                if (trace->config->database) {
                                    if (icmp->quoteTTL() <= it->second.splitTTL) {
                                        if (trace->config->database->exist(icmp->getSrc6(), icmp->tv.tv_sec)) {
                                            it->second.backwardComplete = true;
                                        } else {
                                            trace->config->database->insert(icmp->getSrc6(), icmp->tv.tv_sec);
                                        }
                                    }
                                }
                                if (icmp->quoteTTL() >= it->second.splitTTL) {
                                    if (icmp->quoteTTL() > it->second.farthest_received_forward_ttl) {
                                        it->second.farthest_received_forward_ttl = icmp->quoteTTL();
                                    }
                                    if (trace->config->loopbackdetect) {
                                        if (it->second.fixed_queue.contains(icmp->getSrc6())) {
                                            it->second.forwardComplete = true;
                                        } else {
                                            it->second.fixed_queue.push(icmp->getSrc6());
                                        }
                                    }
                                }
                            }
                        }
                    }
                    /* Fill mode logic. */
                    if (trace->config->fillmode) {
                        if (trace->config->target_control_state_dict) {
                            if ( (icmp->getTTL() >= trace->config->maxttl) and
                            (icmp->getTTL() < trace->config->fillmode)) {
                                if (icmp->getType() == 3) {
                                    auto it = trace->config->target_control_state_dict->dict.find(icmp->true_target);
                                    if (it != trace->config->target_control_state_dict->dict.end()) {
                                        if (!it->second.forwardComplete) {
                                            if (trace->config->count == 0 || (trace->stats->count.load() < trace->config->count)) {
                                                ++trace->stats->count;
                                                ++trace->stats->fills;
                                                trace->probe(icmp->true_target, icmp->getTTL() + 1); 
                                                it->second.forwardProbedTTL++;
                                            }
                                        }
                                    }
                                }
                            }
                        } else {
                            if ( (icmp->getTTL() >= trace->config->maxttl) and
                                (icmp->getTTL() < trace->config->fillmode) ) {
                                ++trace->stats->count;
                                ++trace->stats->fills;
                                trace->probe(icmp->true_target, icmp->getTTL() + 1); 
                            }
                        }
                    }
                    icmp->write(&(trace->config->out), trace->stats->count.load());
                    /* TTL tree histogram */
                    if (trace->ttlhisto.size() > icmp->quoteTTL()) {
                     ttlhisto = trace->ttlhisto[icmp->quoteTTL()];
                     ttlhisto->add(icmp->getSrc6(), elapsed);
                    }
                    if (verbosity > DEBUG)
                     trace->dumpHisto();
                }
                if ((icmp->is_exception) and (exception_dumper)) {
                    memset(&pcap_hdr, 0, sizeof(pcap_hdr));
                    pcap_hdr.ts = current_time;
                    pcap_hdr.caplen = len;
                    pcap_hdr.len = len;
                    pcap_dump((u_char *)exception_dumper, &pcap_hdr, buf);
                    pcap_dump_flush(exception_dumper);
                }
                delete icmp;
            }
        } 
#ifndef _LINUX
	p += BPF_WORDALIGN(bh->bh_hdrlen + bh->bh_caplen);
	if (p < bpfbuf + len) goto reloop;
#endif
    memset(buf, 0, PKTSIZE);
    }
    // Close pcap file handle
    if (pcap_dumper) {
        pcap_dump_close(pcap_dumper);
        pcap_dumper = NULL;
    }
    if (pcap_handle) {
        pcap_close(pcap_handle);
        pcap_handle = NULL;
    }
    if (exception_dumper) {
        pcap_dump_close(exception_dumper);
        exception_dumper = NULL;
    }
    if (exception_handle) {
        pcap_close(exception_handle);
        exception_handle = NULL;
    }
    return NULL;
}
