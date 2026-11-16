/*
 * multicap - High-performance multicast stream capture utility
 * Version 3.0
 *
 * Captures multicast UDP streams to pcap files or raw payload data.
 * Designed for high bitrate streams (>1.5 Gbps) with threaded I/O.
 * Supports SMPTE 2022-7 seamless protection switching capture.
 *
 * Since 3.0 the frames are received with an AF_PACKET TPACKET_V3 mmap ring,
 * so the pcap files hold the real Ethernet frames from the wire (MAC, IP and
 * UDP headers exactly as received) with nanosecond timestamps.
 *
 * Usage:
 *   multicap --multi 239.1.1.1 -i eth0 --port 5000 --pcap output.pcap
 *   multicap --multi 239.1.1.1 -i eth0 --port 5000 --raw output.ts
 *   multicap -7 --redmulti 239.1.1.1 --redport 5000 --redint eth0 \
 *            --bluemulti 239.1.2.1 --blueport 5000 --blueint eth1 \
 *            --redpcap red.pcap --bluepcap blue.pcap
 *
 * Author: Claude (Anthropic), from an idea by Christopher Glover
 * Copyright (c) 2026 Christopher Glover
 * License: MIT
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdatomic.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <time.h>
#include <getopt.h>
#include <limits.h>
#include <poll.h>
#include <endian.h>
#include <pthread.h>
#include <sys/socket.h>
#include <sys/mman.h>
#include <sys/ioctl.h>
#include <sys/sysinfo.h>
#include <sys/utsname.h>
#include <sys/uio.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <fcntl.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <linux/filter.h>
#include <linux/net_tstamp.h>
#include <linux/sockios.h>
#include <linux/virtio_net.h>

/* PCAP file format */
#define PCAP_MAGIC_NSEC      0xa1b23c4d  /* nanosecond-resolution pcap */
#define PCAP_VERSION_MAJOR   2
#define PCAP_VERSION_MINOR   4
#define PCAP_LINKTYPE_EN10MB 1           /* Ethernet */
#define PCAP_SNAPLEN         262144      /* Same as tcpdump */

/* Program version */
#define MULTICAP_VERSION    "3.0"
#define MULTICAP_DATE       "2026-11-16"

/* RTP header size (minimum, without extensions) */
#define RTP_HEADER_SIZE     12

/* Ethernet framing */
#define ETH_HDR_LEN         14
#define VLAN_TAG_LEN        4
#define ETH_VLAN_OVERHEAD   18           /* Ethernet header + one 802.1Q tag */

/* Default and limit values */
#define DEFAULT_BUFFER_MB   512
#define MIN_BUFFER_MB       64
#define DEFAULT_KRING_MB    256          /* Kernel RX ring per path */
#define MIN_KRING_MB        1
#define KRING_BLOCK_SIZE    (4u << 20)   /* 4 MiB blocks */
#define KRING_MIN_BLOCKS    8
#define KRING_MIN_BLOCK     (128u << 10) /* Must hold a 64 KiB GRO aggregate */
#define KRING_FRAME_SIZE    2048         /* Nominal; V3 packs frames by size */
#define KRING_BLOCK_TOV_MS  10           /* Hand back partly filled blocks */
#define STATS_INTERVAL_MS   500
#define WRITE_BATCH_RECORDS 1024         /* Ring records per writer batch */
#define WRITE_IOV_MAX       1024         /* IOV_MAX on Linux */
#define SPLIT_SCRATCH_SEGS  512          /* Rebuilt headers per flush */
#define SPLIT_HDR_MAX       128          /* pcap + eth/vlan + IP + UDP */

/* Userspace ring record flags */
#define REC_PAD             0x0001       /* Filler up to the end of the ring */
#define REC_VLAN            0x0002       /* 802.1Q tag was put back */

/* SMPTE 2022-7 path identifiers */
#define PATH_RED            0
#define PATH_BLUE           1
#define MAX_PATHS           2

/* PCAP file header */
#pragma pack(push, 1)
typedef struct {
    uint32_t magic_number;
    uint16_t version_major;
    uint16_t version_minor;
    int32_t  thiszone;
    uint32_t sigfigs;
    uint32_t snaplen;
    uint32_t network;
} pcap_file_header_t;

typedef struct {
    uint32_t ts_sec;
    uint32_t ts_nsec;
    uint32_t incl_len;
    uint32_t orig_len;
} pcap_packet_header_t;
#pragma pack(pop)

/*
 * Userspace ring record. Records are variable length and 16-byte aligned:
 *   rec_hdr_t | pcap_packet_header_t | frame bytes (VLAN tag already restored)
 * The pcap header and frame are contiguous, so the pcap writer hands them to
 * writev() straight from the ring without copying.
 */
typedef struct {
    uint32_t rec_len;       /* Bytes from this header to the next record */
    uint16_t flags;         /* REC_* */
    uint16_t gso_size;      /* UDP payload per datagram if a GRO aggregate */
    uint8_t  gso_type;      /* VIRTIO_NET_HDR_GSO_* (0 = single frame) */
    uint8_t  pad[7];
} rec_hdr_t;

#define REC_ALIGN           16
#define REC_OVERHEAD        (sizeof(rec_hdr_t) + sizeof(pcap_packet_header_t))

/* Single-producer / single-consumer byte ring. head and tail count bytes
 * ever produced/consumed; position in buf is (counter % size). */
typedef struct {
    uint8_t *buf;
    size_t size;                    /* Multiple of REC_ALIGN */
    _Atomic uint64_t head;          /* Written only by the capture thread */
    _Atomic uint64_t tail;          /* Written only by the writer thread */
} byte_ring_t;

/* Counter written by exactly one thread, read by others */
typedef _Atomic uint64_t counter_t;

static inline void ctr_add(counter_t *c, uint64_t n) {
    atomic_store_explicit(c, atomic_load_explicit(c, memory_order_relaxed) + n,
                          memory_order_relaxed);
}

static inline uint64_t ctr_get(counter_t *c) {
    return atomic_load_explicit(c, memory_order_relaxed);
}

/* Per-path statistics */
typedef struct {
    /* Capture thread */
    counter_t frames;           /* Frames put in the userspace ring */
    counter_t bytes;            /* Frame bytes put in the userspace ring */
    counter_t datagrams;        /* UDP datagrams in those frames */
    counter_t ring_drops;       /* Frames lost: userspace ring full */
    counter_t gro_aggregates;   /* Frames that carried several datagrams */
    counter_t oversize;         /* Frames > MTU with no GRO info */
    counter_t hw_stamped;       /* Frames carrying a NIC hardware timestamp */
    /* Writer thread */
    counter_t written;          /* Ring frames written to the output */
    counter_t out_records;      /* pcap records / raw chunks written */
    counter_t bytes_written;    /* Bytes written to the output file */
    /* Stats thread, then main (never both at once) */
    counter_t kernel_packets;   /* tp_packets from PACKET_STATISTICS */
    counter_t kernel_drops;     /* tp_drops: kernel ring was full */
    counter_t kernel_freezes;   /* tp_freeze_q_cnt */
} path_stats_t;

/* Everything one capture path needs */
typedef struct {
    const char *name;           /* "Red", "Blue" or NULL in single mode */
    const char *color;          /* ANSI colour for the stats line */
    const char *iface;
    const char *group;
    uint16_t port;
    const char *out_file;       /* NULL = this path is not captured */

    int ifindex;
    int mtu;
    struct in_addr group_addr;

    int join_fd;                /* UDP socket that only holds the IGMP join */
    int pkt_fd;                 /* AF_PACKET socket */
    uint8_t *kring;             /* mmap'd TPACKET_V3 ring */
    size_t kring_len;
    unsigned int blk_size;
    unsigned int blk_nr;
    bool vnet;                  /* PACKET_VNET_HDR on: GRO segment size known */

    bool hwts;                  /* Hardware timestamps requested and enabled */
    bool hw_restore;            /* We changed the NIC config; put it back */
    struct hwtstamp_config hw_orig;

    byte_ring_t ring;
    int out_fd;

    pthread_t cap_thr;
    pthread_t wr_thr;
    bool cap_started;
    bool wr_started;
    atomic_bool cap_done;
    atomic_bool fatal;          /* Path hit an unrecoverable error */
    atomic_bool closed;         /* Reader of the output went away (EPIPE) */

    path_stats_t st;
} cap_path_t;

/* Global state */
typedef struct {
    /* Configuration - single stream mode */
    char *multicast_addr;
    char *interface;
    uint16_t port;
    char *output_file;

    /* Configuration - SMPTE 2022-7 mode */
    bool smpte2022_7;
    char *red_multicast_addr;
    char *red_interface;
    uint16_t red_port;
    char *blue_multicast_addr;
    char *blue_interface;
    uint16_t blue_port;
    char *red_pcap_file;
    char *blue_pcap_file;

    /* Common configuration */
    bool pcap_mode;             /* true = pcap, false = raw */
    bool split_gro;             /* Rebuild wire frames from GRO aggregates */
    bool want_hwts;             /* --hwts */
    int duration_secs;
    size_t buffer_mb;
    size_t kring_mb;
    bool quiet;
    bool kernel_has_vnet_udp;   /* Kernel can report UDP GRO segment size */

    /* Runtime */
    atomic_bool running;
    cap_path_t paths[MAX_PATHS];
    int npaths;
    pthread_t stats_thread;
} capture_state_t;

static capture_state_t g_state;

/* Signal handler for graceful shutdown */
static void signal_handler(int sig) {
    (void)sig;
    atomic_store(&g_state.running, false);
}

static bool is_running(void) {
    return atomic_load_explicit(&g_state.running, memory_order_relaxed);
}

/* ============================================================
 * Userspace byte ring
 * ============================================================ */

static int byte_ring_init(byte_ring_t *ring, size_t size_mb) {
    size_t size = size_mb * 1024 * 1024;
    size -= size % REC_ALIGN;

    /* MAP_POPULATE faults the pages in now rather than in the capture
     * thread while the stream is running. */
    void *buf = mmap(NULL, size, PROT_READ | PROT_WRITE,
                     MAP_PRIVATE | MAP_ANONYMOUS | MAP_POPULATE, -1, 0);
    if (buf == MAP_FAILED) {
        return -1;
    }

    /* Lock pages in memory to prevent swapping (needs CAP_IPC_LOCK or a
     * large RLIMIT_MEMLOCK; not fatal if refused) */
    mlock(buf, size);

    ring->buf = buf;
    ring->size = size;
    atomic_init(&ring->head, 0);
    atomic_init(&ring->tail, 0);
    return 0;
}

static void byte_ring_destroy(byte_ring_t *ring) {
    if (ring->buf) {
        munlock(ring->buf, ring->size);
        munmap(ring->buf, ring->size);
        ring->buf = NULL;
    }
}

/* Fill level 0.0 - 1.0 */
static double byte_ring_fill_level(byte_ring_t *ring) {
    if (!ring->buf) return 0.0;
    uint64_t head = atomic_load_explicit(&ring->head, memory_order_relaxed);
    uint64_t tail = atomic_load_explicit(&ring->tail, memory_order_relaxed);
    return (double)(head - tail) / (double)ring->size;
}

/*
 * Reserve space for a record of rec_len bytes (already REC_ALIGN aligned).
 * Returns a pointer to write the record at, or NULL if the ring is full.
 * *new_head receives the head value to publish once the record is written.
 */
static uint8_t *byte_ring_reserve(byte_ring_t *ring, size_t rec_len,
                                  uint64_t *new_head) {
    uint64_t head = atomic_load_explicit(&ring->head, memory_order_relaxed);
    uint64_t tail = atomic_load_explicit(&ring->tail, memory_order_acquire);
    size_t pos = head % ring->size;
    size_t to_end = ring->size - pos;
    size_t need = rec_len;

    if (to_end < rec_len) {
        need += to_end;     /* Pad to the end, record starts at offset 0 */
    }
    if (ring->size - (head - tail) < need) {
        return NULL;
    }

    if (to_end < rec_len) {
        rec_hdr_t *padrec = (rec_hdr_t *)(ring->buf + pos);
        padrec->rec_len = (uint32_t)to_end;
        padrec->flags = REC_PAD;
        pos = 0;
    }
    *new_head = head + need;
    return ring->buf + pos;
}

static inline void byte_ring_publish(byte_ring_t *ring, uint64_t new_head) {
    atomic_store_explicit(&ring->head, new_head, memory_order_release);
}

/* ============================================================
 * Checksums (RFC 1071). The ones' complement sum is independent of byte
 * order, so summing native-endian words and storing the result with
 * memcpy gives the right bytes on the wire.
 * ============================================================ */

static uint64_t csum_partial(const uint8_t *p, size_t len, uint64_t sum) {
    while (len >= 4) {
        uint32_t w;
        memcpy(&w, p, 4);
        sum += w;
        p += 4;
        len -= 4;
    }
    if (len >= 2) {
        uint16_t w;
        memcpy(&w, p, 2);
        sum += w;
        p += 2;
        len -= 2;
    }
    if (len) {
        uint8_t last[2] = { p[0], 0 };
        uint16_t w;
        memcpy(&w, last, 2);
        sum += w;
    }
    return sum;
}

static uint16_t csum_fold(uint64_t sum) {
    while (sum >> 16) {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    return (uint16_t)~sum;
}

/* ============================================================
 * Frame parsing helpers
 * ============================================================ */

/* Locate the UDP payload of an IPv4/UDP frame.
 * eth_len is 14, or 18 when a VLAN tag is in the frame.
 * For a GRO aggregate the payload holds several datagrams back to back. */
static bool frame_udp_payload(const uint8_t *frame, size_t caplen, size_t eth_len,
                              bool aggregate, const uint8_t **payload,
                              size_t *payload_len) {
    if (caplen < eth_len + 20) return false;
    const uint8_t *ip = frame + eth_len;
    size_t ihl = (size_t)(ip[0] & 0x0f) * 4;
    if (ihl < 20 || caplen < eth_len + ihl + 8) return false;

    size_t ip_tot = ((size_t)ip[2] << 8) | ip[3];
    size_t end = caplen;                      /* Never read past the capture */
    if (ip_tot >= ihl + 8 && eth_len + ip_tot < end) {
        end = eth_len + ip_tot;               /* Drop Ethernet padding */
    }
    size_t start = eth_len + ihl + 8;
    size_t len = end - start;

    if (!aggregate) {
        /* A single datagram: the UDP length is authoritative */
        const uint8_t *udp = ip + ihl;
        size_t udp_len = ((size_t)udp[4] << 8) | udp[5];
        if (udp_len >= 8 && udp_len - 8 < len) {
            len = udp_len - 8;
        }
    }
    *payload = frame + start;
    *payload_len = len;
    return true;
}

/* Extract raw payload from a UDP datagram (strips RTP headers automatically).
 * Unchanged from v2.0 apart from taking a pointer and length.
 * Returns pointer to payload and sets payload_len */
static const uint8_t *extract_raw_payload(const uint8_t *data, size_t len,
                                          size_t *payload_len) {
    const uint8_t *payload = data;
    *payload_len = len;

    /* Check for and strip RTP header */
    if (*payload_len > RTP_HEADER_SIZE) {
        /* Check RTP version (bits 6-7 of first byte should be 2) */
        uint8_t rtp_version = (payload[0] >> 6) & 0x03;

        if (rtp_version == 2) {
            size_t rtp_header_len = RTP_HEADER_SIZE;

            /* Check for CSRC count (lower 4 bits of first byte) */
            uint8_t cc = payload[0] & 0x0F;
            rtp_header_len += cc * 4;

            /* Check for extension header (bit 4 of first byte) */
            if (payload[0] & 0x10) {
                if (*payload_len > rtp_header_len + 4) {
                    /* Extension length is in 32-bit words, at offset 2-3 of extension */
                    uint16_t ext_len = (payload[rtp_header_len + 2] << 8) |
                                       payload[rtp_header_len + 3];
                    rtp_header_len += 4 + ext_len * 4;
                }
            }

            /* Check for padding (bit 5 of first byte) */
            if (payload[0] & 0x20) {
                if (*payload_len > 0) {
                    /* Last byte contains padding length */
                    uint8_t padding_len = payload[*payload_len - 1];
                    if (padding_len < *payload_len) {
                        *payload_len -= padding_len;
                    }
                }
            }

            if (rtp_header_len < *payload_len) {
                payload += rtp_header_len;
                *payload_len -= rtp_header_len;

                /* Verify we have valid MPEG-TS data (sync byte 0x47) */
                if (*payload_len >= 188 && payload[0] != 0x47) {
                    /* Try to find sync byte - some implementations add extra bytes */
                    for (size_t i = 0; i < *payload_len - 188 && i < 16; i++) {
                        if (payload[i] == 0x47 &&
                            (*payload_len - i) >= 188 &&
                            ((*payload_len - i) % 188 == 0 ||
                             (*payload_len - i >= 376 && payload[i + 188] == 0x47))) {
                            payload += i;
                            *payload_len -= i;
                            break;
                        }
                    }
                }
            }
        }
    }

    return payload;
}

/* ============================================================
 * Sockets
 * ============================================================ */

/*
 * UDP socket whose only job is to hold the IGMP membership so the switch
 * keeps forwarding the group. It is never bound, so the kernel delivers no
 * datagrams to it; the drop-everything filter and tiny buffer make sure it
 * costs nothing even if that ever changes. Never read from.
 */
static int create_join_socket(cap_path_t *p) {
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        perror("socket(AF_INET)");
        return -1;
    }

    struct sock_filter drop_all[] = {
        BPF_STMT(BPF_RET | BPF_K, 0),
    };
    struct sock_fprog prog = { .len = 1, .filter = drop_all };
    if (setsockopt(sock, SOL_SOCKET, SO_ATTACH_FILTER, &prog, sizeof(prog)) < 0) {
        perror("SO_ATTACH_FILTER (join socket)");
        close(sock);
        return -1;
    }

    int rcvbuf = 4096;      /* Kernel rounds up to its minimum */
    setsockopt(sock, SOL_SOCKET, SO_RCVBUF, &rcvbuf, sizeof(rcvbuf));

    struct ip_mreqn mreq = {0};
    mreq.imr_multiaddr = p->group_addr;
    mreq.imr_address.s_addr = htonl(INADDR_ANY);
    mreq.imr_ifindex = p->ifindex;
    if (setsockopt(sock, IPPROTO_IP, IP_ADD_MEMBERSHIP, &mreq, sizeof(mreq)) < 0) {
        perror("IP_ADD_MEMBERSHIP");
        close(sock);
        return -1;
    }
    return sock;
}

/*
 * Classic BPF equivalent to tcpdump -dd
 *   'udp and dst host <group> and dst port <port>'
 * IPv4 ethertype, protocol UDP, destination address, not a non-first
 * fragment, then the destination port behind a variable-length IP header.
 */
static void build_filter(struct sock_filter *f, uint32_t group_host, uint16_t port) {
    struct sock_filter prog[] = {
        /* 0 */ BPF_STMT(BPF_LD  | BPF_H   | BPF_ABS, 12),            /* ethertype */
        /* 1 */ BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, ETH_P_IP, 0, 10),
        /* 2 */ BPF_STMT(BPF_LD  | BPF_B   | BPF_ABS, 23),            /* IP proto */
        /* 3 */ BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, IPPROTO_UDP, 0, 8),
        /* 4 */ BPF_STMT(BPF_LD  | BPF_W   | BPF_ABS, 30),            /* IP dst */
        /* 5 */ BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, group_host, 0, 6),
        /* 6 */ BPF_STMT(BPF_LD  | BPF_H   | BPF_ABS, 20),            /* frag off */
        /* 7 */ BPF_JUMP(BPF_JMP | BPF_JSET | BPF_K, 0x1fff, 4, 0),
        /* 8 */ BPF_STMT(BPF_LDX | BPF_B   | BPF_MSH, 14),            /* X = IHL*4 */
        /* 9 */ BPF_STMT(BPF_LD  | BPF_H   | BPF_IND, 16),            /* UDP dport */
        /* 10 */ BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, port, 0, 1),
        /* 11 */ BPF_STMT(BPF_RET | BPF_K, PCAP_SNAPLEN),
        /* 12 */ BPF_STMT(BPF_RET | BPF_K, 0),
    };
    memcpy(f, prog, sizeof(prog));
}

#define FILTER_LEN 13

/* Ask the NIC for hardware receive timestamps; fall back to software. */
static void setup_hw_timestamps(cap_path_t *p) {
    struct ifreq ifr;
    struct hwtstamp_config cfg;

    memset(&ifr, 0, sizeof(ifr));
    memset(&cfg, 0, sizeof(cfg));
    snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "%s", p->iface);
    ifr.ifr_data = (void *)&cfg;

    if (ioctl(p->pkt_fd, SIOCGHWTSTAMP, &ifr) < 0) {
        fprintf(stderr, "Warning: %s does not support hardware timestamps (%s); "
                "using software timestamps\n", p->iface, strerror(errno));
        return;
    }
    p->hw_orig = cfg;

    if (cfg.rx_filter != HWTSTAMP_FILTER_ALL) {
        struct hwtstamp_config want = cfg;
        want.rx_filter = HWTSTAMP_FILTER_ALL;
        ifr.ifr_data = (void *)&want;
        if (ioctl(p->pkt_fd, SIOCSHWTSTAMP, &ifr) < 0 ||
            want.rx_filter != HWTSTAMP_FILTER_ALL) {
            fprintf(stderr, "Warning: could not enable hardware timestamping of all "
                    "packets on %s (%s); using software timestamps\n", p->iface,
                    errno ? strerror(errno) : "NIC chose a narrower filter");
            if (want.rx_filter != cfg.rx_filter) {
                ifr.ifr_data = (void *)&cfg;
                ioctl(p->pkt_fd, SIOCSHWTSTAMP, &ifr);
            }
            return;
        }
        p->hw_restore = true;
    }

    int req = SOF_TIMESTAMPING_RAW_HARDWARE;
    if (setsockopt(p->pkt_fd, SOL_PACKET, PACKET_TIMESTAMP, &req, sizeof(req)) < 0) {
        perror("PACKET_TIMESTAMP");
        fprintf(stderr, "Warning: using software timestamps on %s\n", p->iface);
        return;
    }
    p->hwts = true;
}

static void restore_hw_timestamps(cap_path_t *p) {
    if (!p->hw_restore) return;
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) return;
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "%s", p->iface);
    ifr.ifr_data = (void *)&p->hw_orig;
    if (ioctl(fd, SIOCSHWTSTAMP, &ifr) < 0) {
        fprintf(stderr, "Warning: could not restore hardware timestamp settings on %s: %s\n",
                p->iface, strerror(errno));
    }
    close(fd);
    p->hw_restore = false;
}

/*
 * AF_PACKET socket with a TPACKET_V3 RX ring. The order matters: the filter
 * and ring are set up before bind(), so no unfiltered frame ever reaches
 * the ring.
 */
static int create_packet_socket(cap_path_t *p) {
    int sock = socket(AF_PACKET, SOCK_RAW, 0);
    if (sock < 0) {
        perror("socket(AF_PACKET)");
        if (errno == EPERM) {
            fprintf(stderr, "multicap needs CAP_NET_RAW: run as root or "
                    "sudo setcap cap_net_raw,cap_net_admin,cap_sys_nice+ep multicap\n");
        }
        return -1;
    }
    p->pkt_fd = sock;

    int version = TPACKET_V3;
    if (setsockopt(sock, SOL_PACKET, PACKET_VERSION, &version, sizeof(version)) < 0) {
        perror("PACKET_VERSION");
        return -1;
    }

    struct sock_filter filter[FILTER_LEN];
    build_filter(filter, ntohl(p->group_addr.s_addr), p->port);
    struct sock_fprog prog = { .len = FILTER_LEN, .filter = filter };
    if (setsockopt(sock, SOL_SOCKET, SO_ATTACH_FILTER, &prog, sizeof(prog)) < 0) {
        perror("SO_ATTACH_FILTER");
        return -1;
    }

    /* A virtio_net_hdr in front of each frame tells us the datagram size
     * inside GRO aggregates. Only on kernels that can describe UDP GRO:
     * older ones would drop those frames instead. */
    if (g_state.kernel_has_vnet_udp) {
        int one = 1;
        if (setsockopt(sock, SOL_PACKET, PACKET_VNET_HDR, &one, sizeof(one)) == 0) {
            p->vnet = true;
        }
    }

    if (g_state.want_hwts) {
        setup_hw_timestamps(p);
    }

    /* Kernel ring geometry */
    size_t total = g_state.kring_mb * 1024 * 1024;
    unsigned int blk = KRING_BLOCK_SIZE;
    while (blk > KRING_MIN_BLOCK && total / blk < KRING_MIN_BLOCKS) {
        blk >>= 1;
    }
    unsigned int nr = (unsigned int)(total / blk);
    if (nr < 2) nr = 2;

    for (;;) {
        struct tpacket_req3 req;
        memset(&req, 0, sizeof(req));
        req.tp_block_size = blk;
        req.tp_block_nr = nr;
        req.tp_frame_size = KRING_FRAME_SIZE;
        req.tp_frame_nr = (blk / KRING_FRAME_SIZE) * nr;
        req.tp_retire_blk_tov = KRING_BLOCK_TOV_MS;
        req.tp_sizeof_priv = 0;
        req.tp_feature_req_word = 0;

        if (setsockopt(sock, SOL_PACKET, PACKET_RX_RING, &req, sizeof(req)) == 0) {
            break;
        }
        if (errno == ENOMEM && nr > KRING_MIN_BLOCKS) {
            nr /= 2;
            fprintf(stderr, "Warning: kernel ring too large, retrying with %u MB\n",
                    (unsigned int)((size_t)blk * nr >> 20));
            continue;
        }
        perror("PACKET_RX_RING");
        return -1;
    }

    p->blk_size = blk;
    p->blk_nr = nr;
    p->kring_len = (size_t)blk * nr;
    p->kring = mmap(NULL, p->kring_len, PROT_READ | PROT_WRITE, MAP_SHARED, sock, 0);
    if (p->kring == MAP_FAILED) {
        p->kring = NULL;
        perror("mmap(PACKET_RX_RING)");
        return -1;
    }

    struct sockaddr_ll sll;
    memset(&sll, 0, sizeof(sll));
    sll.sll_family = AF_PACKET;
    sll.sll_protocol = htons(ETH_P_ALL);
    sll.sll_ifindex = p->ifindex;
    if (bind(sock, (struct sockaddr *)&sll, sizeof(sll)) < 0) {
        perror("bind(AF_PACKET)");
        return -1;
    }
    return 0;
}

/* Read the kernel ring counters. They reset on every read, so accumulate. */
static void poll_kernel_stats(cap_path_t *p) {
    if (p->pkt_fd < 0) return;
    struct tpacket_stats_v3 st;
    socklen_t len = sizeof(st);
    memset(&st, 0, sizeof(st));
    if (getsockopt(p->pkt_fd, SOL_PACKET, PACKET_STATISTICS, &st, &len) == 0) {
        ctr_add(&p->st.kernel_packets, st.tp_packets);
        ctr_add(&p->st.kernel_drops, st.tp_drops);
        ctr_add(&p->st.kernel_freezes, st.tp_freeze_q_cnt);
    }
}

/* ============================================================
 * Capture thread: kernel ring -> userspace ring
 * ============================================================ */

static void capture_frame(cap_path_t *p, struct tpacket3_hdr *tp) {
    const uint8_t *frame = (const uint8_t *)tp + tp->tp_mac;
    uint32_t snap = tp->tp_snaplen;
    uint32_t wire = tp->tp_len;
    bool vlan = (tp->tp_status & TP_STATUS_VLAN_VALID) && snap >= 12;

    uint8_t gso_type = VIRTIO_NET_HDR_GSO_NONE;
    uint16_t gso_size = 0;
    if (p->vnet) {
        struct virtio_net_hdr vh;
        memcpy(&vh, frame - sizeof(vh), sizeof(vh));
        gso_type = vh.gso_type & ~VIRTIO_NET_HDR_GSO_ECN;
        gso_size = le16toh(vh.gso_size);
        if (gso_type != VIRTIO_NET_HDR_GSO_UDP_L4 || gso_size == 0) {
            gso_type = VIRTIO_NET_HDR_GSO_NONE;
            gso_size = 0;
        }
    }

    uint32_t stored = snap + (vlan ? VLAN_TAG_LEN : 0);
    size_t rec_len = (REC_OVERHEAD + stored + REC_ALIGN - 1) & ~(size_t)(REC_ALIGN - 1);

    uint64_t new_head;
    uint8_t *rec = byte_ring_reserve(&p->ring, rec_len, &new_head);
    if (!rec) {
        ctr_add(&p->st.ring_drops, 1);
        return;
    }

    rec_hdr_t *rh = (rec_hdr_t *)rec;
    rh->rec_len = (uint32_t)rec_len;
    rh->flags = vlan ? REC_VLAN : 0;
    rh->gso_size = gso_size;
    rh->gso_type = gso_type;

    pcap_packet_header_t *ph = (pcap_packet_header_t *)(rec + sizeof(rec_hdr_t));
    ph->ts_sec = tp->tp_sec;
    ph->ts_nsec = tp->tp_nsec;
    ph->incl_len = stored;
    ph->orig_len = wire + (vlan ? VLAN_TAG_LEN : 0);

    uint8_t *dst = rec + REC_OVERHEAD;
    if (vlan) {
        /* NIC stripped the 802.1Q tag; put it back after the MAC addresses */
        uint16_t tpid = (tp->tp_status & TP_STATUS_VLAN_TPID_VALID)
                        ? tp->hv1.tp_vlan_tpid : ETH_P_8021Q;
        uint16_t tci = tp->hv1.tp_vlan_tci;
        memcpy(dst, frame, 12);
        dst[12] = tpid >> 8;
        dst[13] = tpid & 0xff;
        dst[14] = tci >> 8;
        dst[15] = tci & 0xff;
        memcpy(dst + 16, frame + 12, snap - 12);
    } else {
        memcpy(dst, frame, snap);
    }

    byte_ring_publish(&p->ring, new_head);

    /* Statistics */
    uint64_t dgrams = 1;
    if (gso_size) {
        const uint8_t *pl;
        size_t pl_len;
        if (frame_udp_payload(dst, stored, vlan ? ETH_VLAN_OVERHEAD : ETH_HDR_LEN,
                              true, &pl, &pl_len) && pl_len > 0) {
            dgrams = (pl_len + gso_size - 1) / gso_size;
        }
        ctr_add(&p->st.gro_aggregates, 1);
    } else if (wire > (uint32_t)p->mtu + ETH_HDR_LEN) {
        ctr_add(&p->st.oversize, 1);
    }
    if (tp->tp_status & TP_STATUS_TS_RAW_HARDWARE) {
        ctr_add(&p->st.hw_stamped, 1);
    }
    ctr_add(&p->st.frames, 1);
    ctr_add(&p->st.bytes, stored);
    ctr_add(&p->st.datagrams, dgrams);
}

/* Walk every block the kernel has handed to us. Returns blocks consumed. */
static unsigned int drain_blocks(cap_path_t *p, unsigned int *cur) {
    unsigned int done = 0;
    for (;;) {
        struct tpacket_block_desc *bd =
            (struct tpacket_block_desc *)(p->kring + (size_t)*cur * p->blk_size);
        uint32_t status = __atomic_load_n(&bd->hdr.bh1.block_status, __ATOMIC_ACQUIRE);
        if (!(status & TP_STATUS_USER)) {
            return done;
        }

        uint32_t n = bd->hdr.bh1.num_pkts;
        struct tpacket3_hdr *tp =
            (struct tpacket3_hdr *)((uint8_t *)bd + bd->hdr.bh1.offset_to_first_pkt);
        for (uint32_t i = 0; i < n; i++) {
            capture_frame(p, tp);
            tp = (struct tpacket3_hdr *)((uint8_t *)tp + tp->tp_next_offset);
        }

        /* Hand the block back to the kernel */
        __atomic_store_n(&bd->hdr.bh1.block_status, TP_STATUS_KERNEL, __ATOMIC_RELEASE);
        *cur = (*cur + 1) % p->blk_nr;
        done++;
    }
}

static void *capture_thread_func(void *arg) {
    cap_path_t *p = arg;

    /* Set thread to high priority (needs CAP_SYS_NICE; ignored otherwise) */
    struct sched_param param = { .sched_priority = 99 };
    pthread_setschedparam(pthread_self(), SCHED_FIFO, &param);

    struct pollfd pfd = { .fd = p->pkt_fd, .events = POLLIN | POLLERR };
    unsigned int cur = 0;

    while (is_running()) {
        if (drain_blocks(p, &cur) == 0) {
            int r = poll(&pfd, 1, 100);
            if (r < 0 && errno != EINTR) {
                perror("poll");
                atomic_store(&p->fatal, true);
                atomic_store(&g_state.running, false);
                break;
            }
        }
    }

    /* Collect whatever the kernel retires in the next block timeout */
    struct timespec ts = { 0, (KRING_BLOCK_TOV_MS * 2) * 1000000L };
    nanosleep(&ts, NULL);
    drain_blocks(p, &cur);

    atomic_store_explicit(&p->cap_done, true, memory_order_release);
    return NULL;
}

/* ============================================================
 * Writer thread: userspace ring -> file
 * ============================================================ */

typedef struct {
    cap_path_t *p;
    struct iovec iov[WRITE_IOV_MAX];
    int iov_count;
    size_t iov_bytes;
    uint64_t pending_records;
    uint8_t (*scratch)[SPLIT_HDR_MAX];
    int scratch_used;
    bool failed;
} writer_ctx_t;

/* writev() everything queued, coping with short writes and EINTR */
static void writer_flush(writer_ctx_t *w) {
    struct iovec *iov = w->iov;
    int cnt = w->iov_count;

    while (cnt > 0 && !w->failed) {
        ssize_t n = writev(w->p->out_fd, iov, cnt);
        if (n < 0) {
            if (errno == EINTR) continue;
            if (errno == EPIPE) {
                /* e.g. "--pcap - | tcpdump -c 100": the reader is done */
                atomic_store(&w->p->closed, true);
            } else {
                fprintf(stderr, "\nError: write to %s failed: %s\n",
                        w->p->out_file, strerror(errno));
            }
            w->failed = true;
            break;
        }
        size_t left = (size_t)n;
        while (cnt > 0 && left >= iov->iov_len) {
            left -= iov->iov_len;
            iov++;
            cnt--;
        }
        if (cnt > 0) {
            iov->iov_base = (uint8_t *)iov->iov_base + left;
            iov->iov_len -= left;
        }
    }

    if (!w->failed) {
        ctr_add(&w->p->st.bytes_written, w->iov_bytes);
        ctr_add(&w->p->st.out_records, w->pending_records);
    }
    w->iov_count = 0;
    w->iov_bytes = 0;
    w->pending_records = 0;
    w->scratch_used = 0;
}

static inline void writer_add(writer_ctx_t *w, const void *base, size_t len) {
    if (w->iov_count == WRITE_IOV_MAX) {
        writer_flush(w);
    }
    w->iov[w->iov_count].iov_base = (void *)base;
    w->iov[w->iov_count].iov_len = len;
    w->iov_count++;
    w->iov_bytes += len;
}

/*
 * Turn one GRO aggregate back into the datagrams that were on the wire.
 * Each gets a copy of the Ethernet (and VLAN) header and the IP and UDP
 * headers with the lengths, IP ID and checksums the sender's frames had,
 * following the same rules the kernel uses when it segments a UDP GSO
 * packet (IP ID +1 per datagram, UDP checksum recomputed unless it was 0).
 */
static void write_split(writer_ctx_t *w, const pcap_packet_header_t *ph,
                        const uint8_t *frame, size_t eth_len, uint16_t gso_size) {
    const uint8_t *payload;
    size_t payload_len;
    if (!frame_udp_payload(frame, ph->incl_len, eth_len, true, &payload, &payload_len)) {
        writer_add(w, ph, sizeof(*ph) + ph->incl_len);
        w->pending_records++;
        return;
    }

    const uint8_t *ip = frame + eth_len;
    size_t ihl = (size_t)(ip[0] & 0x0f) * 4;
    size_t hdr_len = eth_len + ihl + 8;
    if (sizeof(pcap_packet_header_t) + hdr_len > SPLIT_HDR_MAX) {
        writer_add(w, ph, sizeof(*ph) + ph->incl_len);
        w->pending_records++;
        return;
    }
    uint16_t id0 = (uint16_t)((ip[4] << 8) | ip[5]);
    bool udp_csum = (ip[ihl + 6] | ip[ihl + 7]) != 0;

    for (size_t off = 0, i = 0; off < payload_len; off += gso_size, i++) {
        size_t seg = payload_len - off < gso_size ? payload_len - off : gso_size;

        if (w->scratch_used == SPLIT_SCRATCH_SEGS || w->iov_count + 2 > WRITE_IOV_MAX) {
            writer_flush(w);
        }
        uint8_t *s = w->scratch[w->scratch_used++];
        pcap_packet_header_t *sph = (pcap_packet_header_t *)s;
        uint8_t *h = s + sizeof(*sph);

        memcpy(h, frame, hdr_len);
        uint8_t *sip = h + eth_len;
        uint8_t *sudp = sip + ihl;

        size_t tot = ihl + 8 + seg;
        uint16_t id = (uint16_t)(id0 + i);
        sip[2] = tot >> 8;
        sip[3] = tot & 0xff;
        sip[4] = id >> 8;
        sip[5] = id & 0xff;
        sip[10] = sip[11] = 0;
        uint16_t ipc = csum_fold(csum_partial(sip, ihl, 0));
        memcpy(sip + 10, &ipc, 2);

        size_t ulen = 8 + seg;
        sudp[4] = ulen >> 8;
        sudp[5] = ulen & 0xff;
        sudp[6] = sudp[7] = 0;
        if (udp_csum) {
            uint8_t pseudo[12];
            memcpy(pseudo, sip + 12, 8);        /* saddr, daddr */
            pseudo[8] = 0;
            pseudo[9] = IPPROTO_UDP;
            pseudo[10] = ulen >> 8;
            pseudo[11] = ulen & 0xff;
            uint64_t sum = csum_partial(pseudo, sizeof(pseudo), 0);
            sum = csum_partial(sudp, 8, sum);
            sum = csum_partial(payload + off, seg, sum);
            uint16_t uc = csum_fold(sum);
            if (uc == 0) uc = 0xffff;
            memcpy(sudp + 6, &uc, 2);
        }

        sph->ts_sec = ph->ts_sec;
        sph->ts_nsec = ph->ts_nsec;
        sph->incl_len = (uint32_t)(hdr_len + seg);
        sph->orig_len = sph->incl_len;

        writer_add(w, s, sizeof(*sph) + hdr_len);
        writer_add(w, payload + off, seg);
        w->pending_records++;
    }
}

/* Raw mode: UDP payload of each datagram, RTP header removed */
static void write_raw(writer_ctx_t *w, const pcap_packet_header_t *ph,
                      const uint8_t *frame, size_t eth_len, uint16_t gso_size) {
    const uint8_t *payload;
    size_t payload_len;
    bool aggregate = gso_size != 0;
    if (!frame_udp_payload(frame, ph->incl_len, eth_len, aggregate, &payload, &payload_len)) {
        return;
    }
    size_t stride = aggregate ? gso_size : (payload_len ? payload_len : 1);

    for (size_t off = 0; off < payload_len; off += stride) {
        size_t dlen = payload_len - off < stride ? payload_len - off : stride;
        size_t out_len;
        const uint8_t *out = extract_raw_payload(payload + off, dlen, &out_len);
        if (out_len > 0) {
            writer_add(w, out, out_len);
            w->pending_records++;
        }
    }
}

static void *writer_thread_func(void *arg) {
    cap_path_t *p = arg;
    byte_ring_t *ring = &p->ring;

    writer_ctx_t *w = calloc(1, sizeof(*w));
    if (w) {
        w->scratch = malloc(SPLIT_SCRATCH_SEGS * SPLIT_HDR_MAX);
    }
    if (!w || !w->scratch) {
        fprintf(stderr, "Error: Failed to allocate writer buffers\n");
        if (w) free(w);
        atomic_store(&p->fatal, true);
        atomic_store(&g_state.running, false);
        return NULL;
    }
    w->p = p;

    uint64_t tail = atomic_load_explicit(&ring->tail, memory_order_relaxed);

    for (;;) {
        bool done = atomic_load_explicit(&p->cap_done, memory_order_acquire);
        uint64_t head = atomic_load_explicit(&ring->head, memory_order_acquire);

        if (head == tail) {
            if (done || w->failed) break;
            usleep(1000);
            continue;
        }

        uint64_t frames = 0;
        unsigned int records = 0;
        while (tail != head && records < WRITE_BATCH_RECORDS) {
            const uint8_t *rec = ring->buf + (tail % ring->size);
            const rec_hdr_t *rh = (const rec_hdr_t *)rec;
            tail += rh->rec_len;
            records++;
            if (rh->flags & REC_PAD) continue;

            const pcap_packet_header_t *ph =
                (const pcap_packet_header_t *)(rec + sizeof(rec_hdr_t));
            const uint8_t *frame = rec + REC_OVERHEAD;
            size_t eth_len = (rh->flags & REC_VLAN) ? ETH_VLAN_OVERHEAD : ETH_HDR_LEN;

            if (!g_state.pcap_mode) {
                write_raw(w, ph, frame, eth_len, rh->gso_size);
            } else if (g_state.split_gro && rh->gso_size) {
                write_split(w, ph, frame, eth_len, rh->gso_size);
            } else {
                /* The frame exactly as received, straight from the ring */
                writer_add(w, ph, sizeof(*ph) + ph->incl_len);
                w->pending_records++;
            }
            frames++;
        }
        writer_flush(w);

        /* Only now are the slots free for the capture thread to reuse */
        atomic_store_explicit(&ring->tail, tail, memory_order_release);

        if (w->failed) {
            if (!atomic_load(&p->closed)) {
                atomic_store(&p->fatal, true);
            }
            atomic_store(&g_state.running, false);
            break;
        }
        ctr_add(&p->st.written, frames);
    }

    free(w->scratch);
    free(w);
    return NULL;
}

/* ============================================================
 * Statistics
 * ============================================================ */

static void sum_stats(uint64_t *frames, uint64_t *ring_drops, uint64_t *kdrops) {
    *frames = *ring_drops = *kdrops = 0;
    for (int i = 0; i < g_state.npaths; i++) {
        cap_path_t *p = &g_state.paths[i];
        if (!p->out_file) continue;
        *frames += ctr_get(&p->st.frames);
        *ring_drops += ctr_get(&p->st.ring_drops);
        *kdrops += ctr_get(&p->st.kernel_drops);
    }
}

static double now_sec(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec + ts.tv_nsec / 1e9;
}

static void *stats_thread_func(void *arg) {
    (void)arg;

    uint64_t last_bytes = 0;
    double last_time = now_sec();

    while (is_running()) {
        usleep(STATS_INTERVAL_MS * 1000);

        double now = now_sec();
        double elapsed = now - last_time;
        uint64_t cur_bytes = 0;
        double fill = 0;
        double fills[MAX_PATHS] = {0};

        for (int i = 0; i < g_state.npaths; i++) {
            cap_path_t *p = &g_state.paths[i];
            if (!p->out_file) continue;
            poll_kernel_stats(p);
            cur_bytes += ctr_get(&p->st.bytes);
            fills[i] = byte_ring_fill_level(&p->ring) * 100.0;
            if (fills[i] > fill) fill = fills[i];
        }

        if (g_state.quiet) {
            last_bytes = cur_bytes;
            last_time = now;
            continue;
        }

        double mbps = elapsed > 0 ? ((cur_bytes - last_bytes) * 8.0) / (elapsed * 1e6) : 0;
        uint64_t frames, rdrops, kdrops;
        sum_stats(&frames, &rdrops, &kdrops);

        /* Determine warning level */
        const char *warning = "";
        const char *warn_color = "";
        const char *color_start = "";       /* Buffer fill figure */
        const char *color_end = "";

        if (fill > 90.0) {
            color_start = "\033[1;31m";
        } else if (fill > 75.0) {
            color_start = "\033[1;33m";
        } else if (fill > 50.0) {
            color_start = "\033[33m";
        }
        if (*color_start) color_end = "\033[0m";

        if (fill > 90.0 || rdrops > 0) {
            warn_color = "\033[1;31m";
            warning = " ** DISK TOO SLOW - DROPPING PACKETS **";
        } else if (kdrops > 0) {
            warn_color = "\033[1;31m";
            warning = " ** KERNEL RING DROPS - capture CPU too slow **";
        } else if (fill > 75.0) {
            warn_color = "\033[1;33m";
            warning = " * WARNING: Buffer filling - disk may be too slow *";
        } else if (fill > 50.0) {
            warn_color = "\033[33m";
            warning = " (buffer elevated)";
        }
        const char *warn_end = *warn_color ? "\033[0m" : "";

        const char *rd_on = rdrops > 0 ? "\033[1;31m" : "";
        const char *rd_off = rdrops > 0 ? "\033[0m" : "";
        const char *kd_on = kdrops > 0 ? "\033[1;31m" : "";
        const char *kd_off = kdrops > 0 ? "\033[0m" : "";

        if (g_state.smpte2022_7) {
            fprintf(stderr, "\r\033[K");
            for (int i = 0; i < g_state.npaths; i++) {
                cap_path_t *p = &g_state.paths[i];
                if (!p->out_file) continue;
                fprintf(stderr, "%s%s: %lu (%.1f%%)\033[0m | ", p->color, p->name,
                        ctr_get(&p->st.frames), fills[i]);
            }
            fprintf(stderr, "%sRing drops: %lu%s | %sKernel drops: %lu%s | %.1f Mbps%s%s%s",
                    rd_on, rdrops, rd_off, kd_on, kdrops, kd_off, mbps,
                    warn_color, warning, warn_end);
        } else {
            cap_path_t *p = &g_state.paths[0];
            fprintf(stderr, "\r\033[K"
                    "Captured: %lu | Written: %lu | %sRing drops: %lu%s | "
                    "%sKernel drops: %lu%s | Rate: %.1f Mbps | Buffer: %s%.1f%%%s%s%s%s",
                    ctr_get(&p->st.frames), ctr_get(&p->st.written),
                    rd_on, rdrops, rd_off, kd_on, kdrops, kd_off,
                    mbps, color_start, fill, color_end, warn_color, warning, warn_end);
        }

        last_bytes = cur_bytes;
        last_time = now;
    }

    if (!g_state.quiet) {
        fprintf(stderr, "\n");
    }
    return NULL;
}

static double pct(uint64_t part, uint64_t whole) {
    return whole ? 100.0 * (double)part / (double)whole : 0.0;
}

static void print_path_summary(cap_path_t *p, const char *indent) {
    path_stats_t *s = &p->st;
    uint64_t frames = ctr_get(&s->frames);
    uint64_t rdrops = ctr_get(&s->ring_drops);
    uint64_t kdrops = ctr_get(&s->kernel_drops);
    uint64_t seen = frames + rdrops + kdrops;

    fprintf(stderr, "%sFrames captured:    %lu\n", indent, frames);
    if (ctr_get(&s->gro_aggregates) > 0 || ctr_get(&s->datagrams) != frames) {
        fprintf(stderr, "%sUDP datagrams:      %lu (%lu frames were GRO aggregates)\n",
                indent, ctr_get(&s->datagrams), ctr_get(&s->gro_aggregates));
    }
    fprintf(stderr, "%sFrames written:     %lu", indent, ctr_get(&s->written));
    if (ctr_get(&s->out_records) != ctr_get(&s->written)) {
        fprintf(stderr, " (%lu %s)", ctr_get(&s->out_records),
                g_state.pcap_mode ? "pcap records" : "datagram payloads");
    }
    fprintf(stderr, "\n");
    fprintf(stderr, "%sRing drops:         %lu (userspace buffer full - output too slow)\n",
            indent, rdrops);
    fprintf(stderr, "%sKernel drops:       %lu (kernel ring full - capture thread too slow)\n",
            indent, kdrops);
    fprintf(stderr, "%sBytes captured:     %lu (%.2f MB)\n", indent,
            ctr_get(&s->bytes), ctr_get(&s->bytes) / (1024.0 * 1024.0));
    fprintf(stderr, "%sBytes written:      %lu (%.2f MB)\n", indent,
            ctr_get(&s->bytes_written), ctr_get(&s->bytes_written) / (1024.0 * 1024.0));
    if (rdrops + kdrops > 0) {
        fprintf(stderr, "%sDrop rate:          %.4f%%\n", indent, pct(rdrops + kdrops, seen));
    }
    if (g_state.want_hwts) {
        fprintf(stderr, "%sHardware timestamps: %lu of %lu frames%s\n", indent,
                ctr_get(&s->hw_stamped), frames, p->hwts ? "" : " (not available)");
    }
    if (ctr_get(&s->gro_aggregates) > 0 && g_state.pcap_mode && !g_state.split_gro) {
        fprintf(stderr, "%sNote: %s has GRO on, so some pcap records hold several "
                "datagrams.\n%s      Use --split-gro to write one record per datagram.\n",
                indent, p->iface, indent);
    }
    if (ctr_get(&s->oversize) > 0) {
        fprintf(stderr, "%sNote: %lu frames were larger than the MTU and could not be "
                "split\n%s      (kernel too old to report the GRO segment size).\n",
                indent, ctr_get(&s->oversize), indent);
    }
}

/* ============================================================
 * Command line
 * ============================================================ */

static void print_usage(const char *prog) {
    fprintf(stderr,
        "multicap v%s - High-performance multicast stream capture\n\n"
        "Usage: %s [OPTIONS]\n\n"
        "Single stream mode:\n"
        "  --multi, -m ADDR     Multicast group address (e.g., 239.1.1.1)\n"
        "  -i INTERFACE         Network interface (e.g., eth0, ens18)\n"
        "  --port, -p PORT      UDP port number\n"
        "  --pcap FILE          Write Ethernet frames to PCAP file (use '-' for stdout)\n"
        "  --raw FILE           Write raw payload to file (use '-' for stdout)\n\n"
        "SMPTE 2022-7 redundancy mode:\n"
        "  -7                   Enable SMPTE 2022-7 redundancy capture\n"
        "  --redmulti ADDR      Red path multicast address\n"
        "  --redport PORT       Red path UDP port\n"
        "  --redint INTERFACE   Red path network interface\n"
        "  --bluemulti ADDR     Blue path multicast address\n"
        "  --blueport PORT      Blue path UDP port\n"
        "  --blueint INTERFACE  Blue path network interface\n"
        "  --redpcap FILE       Write red path to PCAP file\n"
        "  --bluepcap FILE      Write blue path to PCAP file\n\n"
        "Optional:\n"
        "  --duration, -d SECS  Capture duration in seconds (0 = unlimited)\n"
        "  --buffer, -b MB      Ring buffer size in MB (default: auto, up to 25%% of free RAM)\n"
        "  --kring MB           Kernel receive ring per path in MB (default: %d)\n"
        "  --split-gro          Write each datagram of a GRO aggregate as its own frame\n"
        "  --hwts               Use NIC hardware receive timestamps if available\n"
        "  --quiet, -q          Suppress statistics output\n"
        "  --version, -V        Show version information\n"
        "  --help, -h           Show this help message\n\n"
        "Needs CAP_NET_RAW (root, or: sudo setcap cap_net_raw,cap_net_admin,cap_sys_nice+ep multicap)\n\n"
        "Examples:\n"
        "  Single stream:\n"
        "    %s --multi 239.1.1.1 -i eth0 --port 5000 --pcap capture.pcap\n"
        "    %s --multi 239.1.1.1 -i eth0 --port 5000 --raw stream.ts\n\n"
        "  SMPTE 2022-7 (capture both paths):\n"
        "    %s -7 --redmulti 239.1.1.1 --redport 5000 --redint eth0 \\\n"
        "          --bluemulti 239.1.2.1 --blueport 5000 --blueint eth1 \\\n"
        "          --redpcap red.pcap --bluepcap blue.pcap\n\n"
        "  SMPTE 2022-7 (10 second capture):\n"
        "    %s -7 -d 10 --redmulti 239.1.1.1 --redport 5000 --redint eth0 \\\n"
        "          --bluemulti 239.1.2.1 --blueport 5000 --blueint eth1 \\\n"
        "          --redpcap red.pcap --bluepcap blue.pcap\n\n",
        MULTICAP_VERSION, prog, DEFAULT_KRING_MB, prog, prog, prog, prog);
}

/* Parse command line arguments */
static int parse_args(int argc, char **argv) {
    static struct option long_options[] = {
        {"multi",     required_argument, 0, 'm'},
        {"port",      required_argument, 0, 'p'},
        {"pcap",      required_argument, 0, 'P'},
        {"raw",       required_argument, 0, 'R'},
        {"duration",  required_argument, 0, 'd'},
        {"buffer",    required_argument, 0, 'b'},
        {"quiet",     no_argument,       0, 'q'},
        {"help",      no_argument,       0, 'h'},
        {"version",   no_argument,       0, 'V'},
        /* SMPTE 2022-7 options */
        {"redmulti",  required_argument, 0, 1001},
        {"redport",   required_argument, 0, 1002},
        {"redint",    required_argument, 0, 1003},
        {"bluemulti", required_argument, 0, 1004},
        {"blueport",  required_argument, 0, 1005},
        {"blueint",   required_argument, 0, 1006},
        {"redpcap",   required_argument, 0, 1007},
        {"bluepcap",  required_argument, 0, 1008},
        /* Capture options */
        {"kring",     required_argument, 0, 1101},
        {"split-gro", no_argument,       0, 1102},
        {"hwts",      no_argument,       0, 1103},
        {0, 0, 0, 0}
    };

    g_state.buffer_mb = DEFAULT_BUFFER_MB;
    g_state.kring_mb = DEFAULT_KRING_MB;

    int opt;
    while ((opt = getopt_long(argc, argv, "m:i:p:d:b:qhV7", long_options, NULL)) != -1) {
        switch (opt) {
            case 'm':
                g_state.multicast_addr = optarg;
                break;
            case 'i':
                g_state.interface = optarg;
                break;
            case 'p':
                g_state.port = atoi(optarg);
                break;
            case 'P':
                g_state.output_file = optarg;
                g_state.pcap_mode = true;
                break;
            case 'R':
                g_state.output_file = optarg;
                g_state.pcap_mode = false;
                break;
            case 'd':
                g_state.duration_secs = atoi(optarg);
                break;
            case 'b':
                g_state.buffer_mb = atoi(optarg);
                if (g_state.buffer_mb < MIN_BUFFER_MB) {
                    g_state.buffer_mb = MIN_BUFFER_MB;
                }
                break;
            case 'q':
                g_state.quiet = true;
                break;
            case 'h':
                print_usage(argv[0]);
                exit(0);
            case 'V':
                printf("multicap version %s (%s)\n", MULTICAP_VERSION, MULTICAP_DATE);
                printf("High-performance multicast stream capture utility\n");
                printf("Copyright (c) 2026 Christopher Glover\n");
                exit(0);
            case '7':
                g_state.smpte2022_7 = true;
                break;
            case 1001:
                g_state.red_multicast_addr = optarg;
                break;
            case 1002:
                g_state.red_port = atoi(optarg);
                break;
            case 1003:
                g_state.red_interface = optarg;
                break;
            case 1004:
                g_state.blue_multicast_addr = optarg;
                break;
            case 1005:
                g_state.blue_port = atoi(optarg);
                break;
            case 1006:
                g_state.blue_interface = optarg;
                break;
            case 1007:
                g_state.red_pcap_file = optarg;
                break;
            case 1008:
                g_state.blue_pcap_file = optarg;
                break;
            case 1101: {
                int mb = atoi(optarg);
                g_state.kring_mb = mb < MIN_KRING_MB ? MIN_KRING_MB : (size_t)mb;
                break;
            }
            case 1102:
                g_state.split_gro = true;
                break;
            case 1103:
                g_state.want_hwts = true;
                break;
            default:
                return -1;
        }
    }

    /* Validate required arguments based on mode */
    if (g_state.smpte2022_7) {
        if (!g_state.red_multicast_addr) {
            fprintf(stderr, "Error: Red path multicast address required (--redmulti)\n");
            return -1;
        }
        if (!g_state.red_interface) {
            fprintf(stderr, "Error: Red path interface required (--redint)\n");
            return -1;
        }
        if (g_state.red_port == 0) {
            fprintf(stderr, "Error: Red path port required (--redport)\n");
            return -1;
        }
        if (!g_state.blue_multicast_addr) {
            fprintf(stderr, "Error: Blue path multicast address required (--bluemulti)\n");
            return -1;
        }
        if (!g_state.blue_interface) {
            fprintf(stderr, "Error: Blue path interface required (--blueint)\n");
            return -1;
        }
        if (g_state.blue_port == 0) {
            fprintf(stderr, "Error: Blue path port required (--blueport)\n");
            return -1;
        }
        if (!g_state.red_pcap_file && !g_state.blue_pcap_file) {
            fprintf(stderr, "Error: At least one output required (--redpcap or --bluepcap)\n");
            return -1;
        }
        g_state.pcap_mode = true;
    } else {
        if (!g_state.multicast_addr) {
            fprintf(stderr, "Error: Multicast address required (--multi)\n");
            return -1;
        }
        if (!g_state.interface) {
            fprintf(stderr, "Error: Interface required (-i)\n");
            return -1;
        }
        if (g_state.port == 0) {
            fprintf(stderr, "Error: Port required (--port)\n");
            return -1;
        }
        if (!g_state.output_file) {
            fprintf(stderr, "Error: Output file required (--pcap or --raw)\n");
            return -1;
        }
    }

    return 0;
}

/* Fill in a path's addresses and interface details */
static int init_path(cap_path_t *p, const char *name, const char *color,
                     const char *iface, const char *group, uint16_t port,
                     const char *out_file) {
    memset(p, 0, sizeof(*p));
    p->name = name;
    p->color = color;
    p->iface = iface;
    p->group = group;
    p->port = port;
    p->out_file = out_file;
    p->join_fd = -1;
    p->pkt_fd = -1;
    p->out_fd = -1;
    atomic_init(&p->cap_done, false);
    atomic_init(&p->fatal, false);
    atomic_init(&p->closed, false);

    const char *what = name ? (name[0] == 'R' ? "Red path " : "Blue path ") : "";
    if (inet_aton(group, &p->group_addr) == 0) {
        fprintf(stderr, "Error: Invalid %smulticast address '%s'\n", what, group);
        return -1;
    }
    uint32_t ip = ntohl(p->group_addr.s_addr);
    if ((ip & 0xF0000000) != 0xE0000000) {
        fprintf(stderr, "Error: %s%s is not a multicast address "
                "(224.0.0.0 - 239.255.255.255)\n", what, group);
        return -1;
    }

    p->ifindex = if_nametoindex(iface);
    if (p->ifindex == 0) {
        fprintf(stderr, "Error: Interface '%s' not found\n", iface);
        return -1;
    }

    p->mtu = 1500;
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd >= 0) {
        struct ifreq ifr;
        memset(&ifr, 0, sizeof(ifr));
        snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "%s", iface);
        if (ioctl(fd, SIOCGIFMTU, &ifr) == 0) {
            p->mtu = ifr.ifr_mtu;
        }
        close(fd);
    }
    return 0;
}

/* Calculate buffer size based on available memory */
static size_t calculate_buffer_size(size_t requested_mb) {
    struct sysinfo info;
    if (sysinfo(&info) != 0) {
        return requested_mb;
    }

    /* Calculate 25% of free memory */
    size_t free_mb = (info.freeram * info.mem_unit) / (1024 * 1024);
    size_t auto_mb = free_mb / 4;

    if (auto_mb < MIN_BUFFER_MB) {
        auto_mb = MIN_BUFFER_MB;
    }

    /* If user specified a size (not default), respect it but cap at 25% */
    if (requested_mb != DEFAULT_BUFFER_MB) {
        if (requested_mb > auto_mb) {
            fprintf(stderr, "Warning: Reducing buffer from %zu MB to %zu MB (25%% of free memory)\n",
                    requested_mb, auto_mb);
            return auto_mb;
        }
        return requested_mb;
    }

    return auto_mb;
}

/* UDP GRO aggregates can be described in a virtio_net_hdr from Linux 6.2 */
static bool kernel_supports_vnet_udp(void) {
    struct utsname u;
    int major = 0, minor = 0;
    if (uname(&u) != 0 || sscanf(u.release, "%d.%d", &major, &minor) != 2) {
        return false;
    }
    return major > 6 || (major == 6 && minor >= 2);
}

static int write_pcap_header(int fd) {
    pcap_file_header_t hdr = {
        .magic_number = PCAP_MAGIC_NSEC,
        .version_major = PCAP_VERSION_MAJOR,
        .version_minor = PCAP_VERSION_MINOR,
        .thiszone = 0,
        .sigfigs = 0,
        .snaplen = PCAP_SNAPLEN,
        .network = PCAP_LINKTYPE_EN10MB
    };
    return write(fd, &hdr, sizeof(hdr)) == sizeof(hdr) ? 0 : -1;
}

static void cleanup_path(cap_path_t *p) {
    restore_hw_timestamps(p);
    if (p->kring) munmap(p->kring, p->kring_len);
    p->kring = NULL;
    if (p->pkt_fd >= 0) close(p->pkt_fd);
    p->pkt_fd = -1;
    if (p->join_fd >= 0) close(p->join_fd);
    p->join_fd = -1;
    if (p->out_fd >= 0 && p->out_fd != STDOUT_FILENO) close(p->out_fd);
    p->out_fd = -1;
    byte_ring_destroy(&p->ring);
}

static void cleanup_all(void) {
    for (int i = 0; i < g_state.npaths; i++) {
        cleanup_path(&g_state.paths[i]);
    }
}

int main(int argc, char **argv) {
    if (parse_args(argc, argv) != 0) {
        print_usage(argv[0]);
        return 1;
    }

    /* Describe the capture paths */
    if (g_state.smpte2022_7) {
        g_state.npaths = 2;
        if (init_path(&g_state.paths[PATH_RED], "Red", "\033[31m",
                      g_state.red_interface, g_state.red_multicast_addr,
                      g_state.red_port, g_state.red_pcap_file) != 0 ||
            init_path(&g_state.paths[PATH_BLUE], "Blue", "\033[34m",
                      g_state.blue_interface, g_state.blue_multicast_addr,
                      g_state.blue_port, g_state.blue_pcap_file) != 0) {
            return 1;
        }
    } else {
        g_state.npaths = 1;
        if (init_path(&g_state.paths[0], NULL, "", g_state.interface,
                      g_state.multicast_addr, g_state.port, g_state.output_file) != 0) {
            return 1;
        }
    }

    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    signal(SIGPIPE, SIG_IGN);

    g_state.kernel_has_vnet_udp = kernel_supports_vnet_udp();

    /* Fail fast, before allocating buffers or creating output files */
    int probe = socket(AF_PACKET, SOCK_RAW, 0);
    if (probe < 0) {
        fprintf(stderr, "Error: cannot open a packet socket: %s\n", strerror(errno));
        if (errno == EPERM) {
            fprintf(stderr, "multicap needs CAP_NET_RAW: run as root or\n"
                    "  sudo setcap cap_net_raw,cap_net_admin,cap_sys_nice+ep %s\n", argv[0]);
        }
        return 1;
    }
    close(probe);

    if (!g_state.kernel_has_vnet_udp && !g_state.quiet &&
        (!g_state.pcap_mode || g_state.split_gro)) {
        fprintf(stderr, "Warning: this kernel (< 6.2) cannot report the datagram size inside "
                "GRO aggregates.\n         If the NIC has GRO on (ethtool -k <if>), %s "
                "will not be\n         split into datagrams.\n",
                g_state.pcap_mode ? "--split-gro frames" : "--raw output");
    }

    /* Writing pcap to stdout: keep stderr quiet so the two don't mix up
     * in a terminal (same as v2.0) */
    if (!g_state.smpte2022_7 && strcmp(g_state.output_file, "-") == 0) {
        g_state.quiet = true;
    }

    /* Userspace ring buffers: the memory budget is shared by the paths
     * that are captured */
    g_state.buffer_mb = calculate_buffer_size(g_state.buffer_mb);
    int active = 0;
    for (int i = 0; i < g_state.npaths; i++) {
        if (g_state.paths[i].out_file) active++;
    }
    size_t per_ring_mb = g_state.buffer_mb / (size_t)active;
    if (per_ring_mb < MIN_BUFFER_MB) {
        per_ring_mb = MIN_BUFFER_MB;
    }

    for (int i = 0; i < g_state.npaths; i++) {
        cap_path_t *p = &g_state.paths[i];
        if (!p->out_file) continue;
        if (byte_ring_init(&p->ring, per_ring_mb) != 0) {
            fprintf(stderr, "Error: Failed to create %zu MB ring buffer\n", per_ring_mb);
            cleanup_all();
            return 1;
        }
        if (!g_state.quiet) {
            size_t slot = (REC_OVERHEAD + p->mtu + ETH_VLAN_OVERHEAD + REC_ALIGN - 1)
                          & ~(size_t)(REC_ALIGN - 1);
            fprintf(stderr, "%s%sing buffer: %zu MB (%zu packet slots at MTU %d)\n",
                    p->name ? p->name : "", p->name ? " r" : "R",
                    per_ring_mb, p->ring.size / slot, p->mtu);
        }
    }

    /* Open outputs */
    for (int i = 0; i < g_state.npaths; i++) {
        cap_path_t *p = &g_state.paths[i];
        if (!p->out_file) continue;
        if (strcmp(p->out_file, "-") == 0) {
            p->out_fd = STDOUT_FILENO;
        } else {
            p->out_fd = open(p->out_file, O_WRONLY | O_CREAT | O_TRUNC, 0644);
            if (p->out_fd < 0) {
                fprintf(stderr, "Error: cannot open %s: %s\n", p->out_file, strerror(errno));
                cleanup_all();
                return 1;
            }
        }
        if (g_state.pcap_mode && write_pcap_header(p->out_fd) != 0) {
            fprintf(stderr, "Error: Failed to write PCAP header to %s\n", p->out_file);
            cleanup_all();
            return 1;
        }
    }

    /* Sockets: IGMP join, then the packet ring */
    for (int i = 0; i < g_state.npaths; i++) {
        cap_path_t *p = &g_state.paths[i];
        if (!p->out_file) continue;
        p->join_fd = create_join_socket(p);
        if (p->join_fd < 0 || create_packet_socket(p) != 0) {
            fprintf(stderr, "Error: Failed to set up capture on %s\n", p->iface);
            cleanup_all();
            return 1;
        }
    }

    if (!g_state.quiet) {
        if (g_state.smpte2022_7) {
            fprintf(stderr, "SMPTE 2022-7 Capture:\n");
            for (int i = 0; i < g_state.npaths; i++) {
                cap_path_t *p = &g_state.paths[i];
                fprintf(stderr, "  %-5s %s:%d on %s", p->name, p->group, p->port, p->iface);
                if (p->out_file) {
                    fprintf(stderr, " -> %s", p->out_file);
                } else {
                    fprintf(stderr, " (not captured: no output file)");
                }
                fprintf(stderr, "\n");
            }
        } else {
            cap_path_t *p = &g_state.paths[0];
            fprintf(stderr, "Capturing %s:%d on %s -> %s (%s mode)\n",
                    p->group, p->port, p->iface, p->out_file,
                    g_state.pcap_mode ? "pcap" : "raw");
        }
        for (int i = 0; i < g_state.npaths; i++) {
            cap_path_t *p = &g_state.paths[i];
            if (!p->out_file) continue;
            fprintf(stderr, "  %s%skernel ring %u x %u KB, %s timestamps%s\n",
                    p->name ? p->name : "", p->name ? ": " : "",
                    p->blk_nr, p->blk_size >> 10,
                    p->hwts ? "hardware" : "software",
                    p->vnet ? "" : ", GRO segment size unavailable");
        }
        if (g_state.duration_secs > 0) {
            fprintf(stderr, "Duration: %d seconds\n", g_state.duration_secs);
        }
        fprintf(stderr, "Press Ctrl+C to stop capture\n\n");
    }

    /* Start threads */
    atomic_store(&g_state.running, true);
    for (int i = 0; i < g_state.npaths; i++) {
        cap_path_t *p = &g_state.paths[i];
        if (!p->out_file) continue;
        if (pthread_create(&p->wr_thr, NULL, writer_thread_func, p) == 0) {
            p->wr_started = true;
        }
        if (pthread_create(&p->cap_thr, NULL, capture_thread_func, p) == 0) {
            p->cap_started = true;
        }
        if (!p->wr_started || !p->cap_started) {
            fprintf(stderr, "Error: Failed to start threads\n");
            atomic_store(&g_state.running, false);
            atomic_store(&p->cap_done, true);
        }
    }
    bool stats_started = pthread_create(&g_state.stats_thread, NULL,
                                        stats_thread_func, NULL) == 0;

    /* Wait for Ctrl+C, the duration, or a fatal error */
    double deadline = g_state.duration_secs > 0 ? now_sec() + g_state.duration_secs : 0;
    while (is_running()) {
        usleep(20000);
        if (deadline > 0 && now_sec() >= deadline) {
            atomic_store(&g_state.running, false);
        }
    }

    for (int i = 0; i < g_state.npaths; i++) {
        cap_path_t *p = &g_state.paths[i];
        if (p->cap_started) pthread_join(p->cap_thr, NULL);
    }
    for (int i = 0; i < g_state.npaths; i++) {
        cap_path_t *p = &g_state.paths[i];
        if (p->wr_started) pthread_join(p->wr_thr, NULL);
    }
    if (stats_started) pthread_join(g_state.stats_thread, NULL);

    bool fatal = false;
    for (int i = 0; i < g_state.npaths; i++) {
        cap_path_t *p = &g_state.paths[i];
        if (!p->out_file) continue;
        poll_kernel_stats(p);
        if (atomic_load(&p->fatal)) fatal = true;
    }

    uint64_t frames, rdrops, kdrops;
    sum_stats(&frames, &rdrops, &kdrops);

    /* Final statistics */
    if (!g_state.quiet) {
        fprintf(stderr, "\nCapture complete:\n");
        if (g_state.smpte2022_7) {
            for (int i = 0; i < g_state.npaths; i++) {
                cap_path_t *p = &g_state.paths[i];
                if (!p->out_file) continue;
                fprintf(stderr, "  %s%s path\033[0m (%s:%d on %s -> %s):\n", p->color,
                        p->name, p->group, p->port, p->iface, p->out_file);
                print_path_summary(p, "    ");
            }
            if (rdrops + kdrops > 0) {
                fprintf(stderr, "  Total drop rate:    %.4f%%\n",
                        pct(rdrops + kdrops, frames + rdrops + kdrops));
            }
        } else {
            print_path_summary(&g_state.paths[0], "  ");
        }
    }

    cleanup_all();

    if (fatal) return 1;
    return (rdrops + kdrops > 0) ? 2 : 0;
}
