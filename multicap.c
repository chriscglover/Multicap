/*
 * multicap - High-performance multicast stream capture utility
 * Version 2.0
 * 
 * Captures multicast UDP streams to pcap files or raw payload data.
 * Designed for high bitrate streams (>1.5 Gbps) with threaded I/O.
 * Supports SMPTE 2022-7 seamless protection switching capture.
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
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <time.h>
#include <getopt.h>
#include <pthread.h>
#include <sys/socket.h>
#include <sys/mman.h>
#include <sys/sysinfo.h>
#include <sys/time.h>
#include <sys/uio.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <fcntl.h>

/* PCAP file format structures */
#define PCAP_MAGIC          0xa1b2c3d4
#define PCAP_VERSION_MAJOR  2
#define PCAP_VERSION_MINOR  4
#define PCAP_LINKTYPE_RAW   101  /* Raw IP */
#define PCAP_LINKTYPE_EN10MB 1   /* Ethernet */

/* Program version */
#define MULTICAP_VERSION    "2.0"
#define MULTICAP_DATE       "2026-01-28"

/* RTP header size (minimum, without extensions) */
#define RTP_HEADER_SIZE     12

/* Default and maximum values */
#define DEFAULT_BUFFER_MB   512
#define MIN_BUFFER_MB       64
#define MAX_PACKET_SIZE     65536
#define STATS_INTERVAL_MS   500
#define WRITE_BATCH_SIZE    256     /* Number of packets to batch for writing */

/* SMPTE 2022-7 constants */
#define PATH_RED            0
#define PATH_BLUE           1
#define SMPTE2022_7_BUFFER  1000    /* Reorder buffer size (packets) */

/* Ring buffer packet entry */
typedef struct {
    uint32_t len;           /* Packet length */
    uint32_t caplen;        /* Captured length */
    struct timeval ts;      /* Timestamp */
    struct sockaddr_in src_addr;  /* Source address */
    uint16_t rtp_seq;       /* RTP sequence number (for 2022-7) */
    uint8_t path;           /* Path identifier: PATH_RED or PATH_BLUE */
    uint8_t data[MAX_PACKET_SIZE];
} packet_entry_t;

/* Ring buffer structure */
typedef struct {
    packet_entry_t *packets;
    size_t capacity;        /* Number of packet slots */
    volatile size_t head;   /* Writer position */
    volatile size_t tail;   /* Reader position */
    volatile bool overflow; /* Overflow flag */
    pthread_mutex_t mutex;
    pthread_cond_t not_empty;
    pthread_cond_t not_full;
} ring_buffer_t;

/* Global state */
typedef struct {
    /* Configuration - single stream mode */
    char *multicast_addr;
    char *interface;
    uint16_t port;
    
    /* Configuration - SMPTE 2022-7 mode */
    bool smpte2022_7;           /* Enable 2022-7 redundancy mode */
    char *red_multicast_addr;
    char *red_interface;
    uint16_t red_port;
    char *blue_multicast_addr;
    char *blue_interface;
    uint16_t blue_port;
    char *red_pcap_file;        /* PCAP file for red path */
    char *blue_pcap_file;       /* PCAP file for blue path */
    
    /* Common configuration */
    char *output_file;
    bool pcap_mode;         /* true = pcap, false = raw */
    int duration_secs;      /* Capture duration (0 = unlimited) */
    size_t buffer_mb;       /* Buffer size in MB */
    bool quiet;             /* Suppress stats output */
    
    /* Runtime state - single stream mode */
    int socket_fd;
    FILE *output_fp;
    int output_fd;              /* File descriptor for direct I/O */
    ring_buffer_t *ring;
    volatile bool running;
    volatile bool writer_done;
    
    /* Runtime state - SMPTE 2022-7 mode */
    int red_socket_fd;
    int blue_socket_fd;
    int red_pcap_fd;            /* File descriptor for red path pcap */
    int blue_pcap_fd;           /* File descriptor for blue path pcap */
    ring_buffer_t *red_ring;
    ring_buffer_t *blue_ring;
    
    /* Statistics - common */
    volatile uint64_t packets_captured;
    volatile uint64_t packets_written;
    volatile uint64_t packets_dropped;
    volatile uint64_t bytes_captured;
    volatile uint64_t bytes_written;
    
    /* Statistics - SMPTE 2022-7 specific */
    volatile uint64_t red_packets;
    volatile uint64_t blue_packets;
    
    /* Threads */
    pthread_t capture_thread;
    pthread_t writer_thread;
    pthread_t stats_thread;
    
    /* SMPTE 2022-7 threads */
    pthread_t red_capture_thread;
    pthread_t blue_capture_thread;
    pthread_t red_writer_thread;
    pthread_t blue_writer_thread;
} capture_state_t;

static capture_state_t g_state = {0};

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
    uint32_t ts_usec;
    uint32_t incl_len;
    uint32_t orig_len;
} pcap_packet_header_t;
#pragma pack(pop)

/* Signal handler for graceful shutdown */
static void signal_handler(int sig) {
    (void)sig;
    g_state.running = false;
}

/* Initialize ring buffer */
static ring_buffer_t *ring_buffer_create(size_t size_mb) {
    ring_buffer_t *ring = calloc(1, sizeof(ring_buffer_t));
    if (!ring) return NULL;
    
    /* Calculate number of packet slots based on memory size */
    size_t total_bytes = size_mb * 1024 * 1024;
    ring->capacity = total_bytes / sizeof(packet_entry_t);
    
    /* Allocate packet array with mmap for better performance */
    ring->packets = mmap(NULL, ring->capacity * sizeof(packet_entry_t),
                         PROT_READ | PROT_WRITE,
                         MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (ring->packets == MAP_FAILED) {
        free(ring);
        return NULL;
    }
    
    /* Lock pages in memory to prevent swapping */
    mlock(ring->packets, ring->capacity * sizeof(packet_entry_t));
    
    ring->head = 0;
    ring->tail = 0;
    ring->overflow = false;
    
    pthread_mutex_init(&ring->mutex, NULL);
    pthread_cond_init(&ring->not_empty, NULL);
    pthread_cond_init(&ring->not_full, NULL);
    
    return ring;
}

/* Destroy ring buffer */
static void ring_buffer_destroy(ring_buffer_t *ring) {
    if (!ring) return;
    
    pthread_mutex_destroy(&ring->mutex);
    pthread_cond_destroy(&ring->not_empty);
    pthread_cond_destroy(&ring->not_full);
    
    if (ring->packets && ring->packets != MAP_FAILED) {
        munlock(ring->packets, ring->capacity * sizeof(packet_entry_t));
        munmap(ring->packets, ring->capacity * sizeof(packet_entry_t));
    }
    
    free(ring);
}

/* Get buffer fill level (0.0 - 1.0) */
static double ring_buffer_fill_level(ring_buffer_t *ring) {
    size_t head = ring->head;
    size_t tail = ring->tail;
    size_t used;
    
    if (head >= tail) {
        used = head - tail;
    } else {
        used = ring->capacity - tail + head;
    }
    
    return (double)used / (double)ring->capacity;
}

/* Extract RTP sequence number from packet data */
static uint16_t extract_rtp_seq(const uint8_t *data, size_t len) {
    if (len < RTP_HEADER_SIZE) return 0;
    
    /* Check RTP version */
    uint8_t rtp_version = (data[0] >> 6) & 0x03;
    if (rtp_version != 2) return 0;
    
    /* Sequence number is bytes 2-3 (big endian) */
    return (data[2] << 8) | data[3];
}

/* Push packet to ring buffer (non-blocking) */
static bool ring_buffer_push(ring_buffer_t *ring, const uint8_t *data, 
                             size_t len, struct timeval *ts,
                             struct sockaddr_in *src_addr,
                             uint8_t path) {
    size_t next_head = (ring->head + 1) % ring->capacity;
    
    /* Check if buffer is full */
    if (next_head == ring->tail) {
        ring->overflow = true;
        return false;
    }
    
    packet_entry_t *entry = &ring->packets[ring->head];
    entry->len = len;
    entry->caplen = (len > MAX_PACKET_SIZE) ? MAX_PACKET_SIZE : len;
    entry->ts = *ts;
    entry->src_addr = *src_addr;
    entry->path = path;
    entry->rtp_seq = extract_rtp_seq(data, len);
    memcpy(entry->data, data, entry->caplen);
    
    /* Memory barrier for lock-free operation */
    __sync_synchronize();
    ring->head = next_head;
    
    /* Signal writer thread */
    pthread_cond_signal(&ring->not_empty);
    
    return true;
}

/* Pop multiple packets from ring buffer (non-blocking, returns count) */
static size_t ring_buffer_pop_batch(ring_buffer_t *ring, packet_entry_t **batch, 
                                    size_t max_count) {
    size_t count = 0;
    
    pthread_mutex_lock(&ring->mutex);
    
    while (count < max_count && ring->head != ring->tail) {
        batch[count] = &ring->packets[ring->tail];
        ring->tail = (ring->tail + 1) % ring->capacity;
        count++;
    }
    
    pthread_mutex_unlock(&ring->mutex);
    
    return count;
}

/* Create and configure multicast socket */
static int create_multicast_socket(const char *mcast_addr, const char *iface, 
                                   uint16_t port) {
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        perror("socket");
        return -1;
    }
    
    /* Allow address reuse */
    int reuse = 1;
    if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse)) < 0) {
        perror("SO_REUSEADDR");
        close(sock);
        return -1;
    }
    
    /* Set large receive buffer */
    int rcvbuf = 64 * 1024 * 1024;  /* 64 MB */
    if (setsockopt(sock, SOL_SOCKET, SO_RCVBUF, &rcvbuf, sizeof(rcvbuf)) < 0) {
        /* Try smaller buffer */
        rcvbuf = 8 * 1024 * 1024;
        setsockopt(sock, SOL_SOCKET, SO_RCVBUF, &rcvbuf, sizeof(rcvbuf));
    }
    
    /* Bind to port */
    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    
    if (bind(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("bind");
        close(sock);
        return -1;
    }
    
    /* Join multicast group */
    struct ip_mreqn mreq = {0};
    mreq.imr_multiaddr.s_addr = inet_addr(mcast_addr);
    mreq.imr_address.s_addr = htonl(INADDR_ANY);
    mreq.imr_ifindex = if_nametoindex(iface);
    
    if (mreq.imr_ifindex == 0) {
        fprintf(stderr, "Error: Interface '%s' not found\n", iface);
        close(sock);
        return -1;
    }
    
    if (setsockopt(sock, IPPROTO_IP, IP_ADD_MEMBERSHIP, &mreq, sizeof(mreq)) < 0) {
        perror("IP_ADD_MEMBERSHIP");
        close(sock);
        return -1;
    }
    
    /* Bind to specific interface */
    if (setsockopt(sock, SOL_SOCKET, SO_BINDTODEVICE, iface, strlen(iface) + 1) < 0) {
        /* Not fatal, but less optimal */
        fprintf(stderr, "Warning: Could not bind to interface (need root?)\n");
    }
    
    /* Set receive timeout so we can check for shutdown */
    struct timeval tv = { .tv_sec = 0, .tv_usec = 100000 };  /* 100ms */
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    
    return sock;
}

/* Structure to hold prepared PCAP packet data */
typedef struct {
    pcap_packet_header_t phdr;
    uint8_t packet[MAX_PACKET_SIZE + 28];
    size_t packet_len;
} prepared_pcap_packet_t;

/* Prepare a packet for PCAP output (builds headers, returns total size) */
static size_t prepare_pcap_packet(packet_entry_t *pkt, prepared_pcap_packet_t *prepared) {
    size_t total_len = pkt->caplen + 28;  /* IP (20) + UDP (8) */
    
    /* IP header */
    struct iphdr *ip = (struct iphdr *)prepared->packet;
    ip->version = 4;
    ip->ihl = 5;
    ip->tos = 0;
    ip->tot_len = htons(total_len);
    ip->id = 0;
    ip->frag_off = 0;
    ip->ttl = 64;
    ip->protocol = IPPROTO_UDP;
    ip->check = 0;
    ip->saddr = pkt->src_addr.sin_addr.s_addr;
    ip->daddr = inet_addr(g_state.multicast_addr);
    
    /* UDP header */
    struct udphdr *udp = (struct udphdr *)(prepared->packet + 20);
    udp->source = pkt->src_addr.sin_port;
    udp->dest = htons(g_state.port);
    udp->len = htons(pkt->caplen + 8);
    udp->check = 0;
    
    /* Payload */
    memcpy(prepared->packet + 28, pkt->data, pkt->caplen);
    
    /* PCAP packet header */
    prepared->phdr.ts_sec = pkt->ts.tv_sec;
    prepared->phdr.ts_usec = pkt->ts.tv_usec;
    prepared->phdr.incl_len = total_len;
    prepared->phdr.orig_len = pkt->len + 28;
    
    prepared->packet_len = total_len;
    
    return sizeof(pcap_packet_header_t) + total_len;
}

/* Write batch of PCAP packets using writev for efficiency */
static size_t write_pcap_batch(int fd, packet_entry_t **batch, size_t count,
                                prepared_pcap_packet_t *prepared_packets) {
    struct iovec iov[WRITE_BATCH_SIZE * 2];  /* 2 iovecs per packet (header + data) */
    size_t total_bytes = 0;
    size_t iov_count = 0;
    
    /* Build iovec array - each packet needs header + data */
    for (size_t i = 0; i < count && iov_count < WRITE_BATCH_SIZE * 2; i++) {
        prepare_pcap_packet(batch[i], &prepared_packets[i]);
        
        /* PCAP packet header */
        iov[iov_count].iov_base = &prepared_packets[i].phdr;
        iov[iov_count].iov_len = sizeof(pcap_packet_header_t);
        total_bytes += sizeof(pcap_packet_header_t);
        iov_count++;
        
        /* Packet data */
        iov[iov_count].iov_base = prepared_packets[i].packet;
        iov[iov_count].iov_len = prepared_packets[i].packet_len;
        total_bytes += prepared_packets[i].packet_len;
        iov_count++;
    }
    
    if (iov_count == 0) {
        return count;
    }
    
    /* Single system call for all packets */
    ssize_t written = writev(fd, iov, iov_count);
    
    if (written < 0) {
        return 0;
    }
    
    return (size_t)written == total_bytes ? count : 0;
}

/* Extract raw payload from packet (strips RTP headers automatically) 
 * Returns pointer to payload and sets payload_len */
static uint8_t *extract_raw_payload(packet_entry_t *pkt, size_t *payload_len) {
    uint8_t *payload = pkt->data;
    *payload_len = pkt->caplen;
    
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

/* Write batch of raw packets using writev for efficiency */
static size_t write_raw_batch(int fd, packet_entry_t **batch, size_t count) {
    struct iovec iov[WRITE_BATCH_SIZE];
    size_t payload_lens[WRITE_BATCH_SIZE];
    size_t total_bytes = 0;
    size_t iov_count = 0;
    
    /* Build iovec array */
    for (size_t i = 0; i < count && iov_count < WRITE_BATCH_SIZE; i++) {
        uint8_t *payload = extract_raw_payload(batch[i], &payload_lens[i]);
        if (payload_lens[i] > 0) {
            iov[iov_count].iov_base = payload;
            iov[iov_count].iov_len = payload_lens[i];
            total_bytes += payload_lens[i];
            iov_count++;
        }
    }
    
    if (iov_count == 0) {
        return count;  /* All empty, but not an error */
    }
    
    /* Single system call for all packets */
    ssize_t written = writev(fd, iov, iov_count);
    
    if (written < 0) {
        return 0;
    }
    
    return (size_t)written == total_bytes ? count : 0;
}

/* Capture thread - receives packets from network */
static void *capture_thread_func(void *arg) {
    (void)arg;
    
    uint8_t buffer[MAX_PACKET_SIZE];
    struct sockaddr_in src_addr;
    socklen_t addr_len = sizeof(src_addr);
    
    /* Set thread to high priority */
    struct sched_param param = { .sched_priority = 99 };
    pthread_setschedparam(pthread_self(), SCHED_FIFO, &param);
    
    time_t start_time = time(NULL);
    
    while (g_state.running) {
        /* Check duration limit */
        if (g_state.duration_secs > 0) {
            if (time(NULL) - start_time >= g_state.duration_secs) {
                g_state.running = false;
                break;
            }
        }
        
        /* Receive packet */
        ssize_t len = recvfrom(g_state.socket_fd, buffer, sizeof(buffer), 0,
                               (struct sockaddr *)&src_addr, &addr_len);
        
        if (len < 0) {
            if (errno == EINTR) continue;
            if (errno == EAGAIN || errno == EWOULDBLOCK) continue;
            perror("recvfrom");
            break;
        }
        
        /* Get timestamp */
        struct timeval ts;
        gettimeofday(&ts, NULL);
        
        /* Push to ring buffer (use PATH_RED for single stream mode) */
        if (ring_buffer_push(g_state.ring, buffer, len, &ts, &src_addr, PATH_RED)) {
            __sync_fetch_and_add(&g_state.packets_captured, 1);
            __sync_fetch_and_add(&g_state.bytes_captured, len);
        } else {
            __sync_fetch_and_add(&g_state.packets_dropped, 1);
        }
    }
    
    return NULL;
}

/* ============================================================
 * SMPTE 2022-7 Redundancy Mode Functions
 * ============================================================ */

/* Red path capture thread */
static void *red_capture_thread_func(void *arg) {
    (void)arg;
    
    uint8_t buffer[MAX_PACKET_SIZE];
    struct sockaddr_in src_addr;
    socklen_t addr_len = sizeof(src_addr);
    
    /* Set thread to high priority */
    struct sched_param param = { .sched_priority = 99 };
    pthread_setschedparam(pthread_self(), SCHED_FIFO, &param);
    
    time_t start_time = time(NULL);
    
    while (g_state.running) {
        /* Check duration limit */
        if (g_state.duration_secs > 0) {
            if (time(NULL) - start_time >= g_state.duration_secs) {
                g_state.running = false;
                break;
            }
        }
        
        ssize_t len = recvfrom(g_state.red_socket_fd, buffer, sizeof(buffer), 0,
                               (struct sockaddr *)&src_addr, &addr_len);
        
        if (len < 0) {
            if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK) continue;
            break;
        }
        
        struct timeval ts;
        gettimeofday(&ts, NULL);
        
        if (ring_buffer_push(g_state.red_ring, buffer, len, &ts, &src_addr, PATH_RED)) {
            __sync_fetch_and_add(&g_state.red_packets, 1);
            __sync_fetch_and_add(&g_state.bytes_captured, len);
        } else {
            __sync_fetch_and_add(&g_state.packets_dropped, 1);
        }
    }
    
    return NULL;
}

/* Blue path capture thread */
static void *blue_capture_thread_func(void *arg) {
    (void)arg;
    
    uint8_t buffer[MAX_PACKET_SIZE];
    struct sockaddr_in src_addr;
    socklen_t addr_len = sizeof(src_addr);
    
    /* Set thread to high priority */
    struct sched_param param = { .sched_priority = 99 };
    pthread_setschedparam(pthread_self(), SCHED_FIFO, &param);
    
    time_t start_time = time(NULL);
    
    while (g_state.running) {
        /* Check duration limit */
        if (g_state.duration_secs > 0) {
            if (time(NULL) - start_time >= g_state.duration_secs) {
                g_state.running = false;
                break;
            }
        }
        
        ssize_t len = recvfrom(g_state.blue_socket_fd, buffer, sizeof(buffer), 0,
                               (struct sockaddr *)&src_addr, &addr_len);
        
        if (len < 0) {
            if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK) continue;
            break;
        }
        
        struct timeval ts;
        gettimeofday(&ts, NULL);
        
        if (ring_buffer_push(g_state.blue_ring, buffer, len, &ts, &src_addr, PATH_BLUE)) {
            __sync_fetch_and_add(&g_state.blue_packets, 1);
            __sync_fetch_and_add(&g_state.bytes_captured, len);
        } else {
            __sync_fetch_and_add(&g_state.packets_dropped, 1);
        }
    }
    
    return NULL;
}

/* Red path writer thread - writes red pcap file */
static void *red_writer_thread_func(void *arg) {
    (void)arg;
    
    packet_entry_t *batch[WRITE_BATCH_SIZE];
    prepared_pcap_packet_t *prepared_packets = malloc(WRITE_BATCH_SIZE * sizeof(prepared_pcap_packet_t));
    
    if (!prepared_packets) {
        fprintf(stderr, "Error: Failed to allocate red PCAP buffer\n");
        return NULL;
    }
    
    while (g_state.running || g_state.red_ring->head != g_state.red_ring->tail) {
        size_t count = ring_buffer_pop_batch(g_state.red_ring, batch, WRITE_BATCH_SIZE);
        
        if (count == 0) {
            usleep(1000);
            continue;
        }
        
        /* Build and write PCAP packets */
        struct iovec iov[WRITE_BATCH_SIZE * 2];
        size_t iov_count = 0;
        
        for (size_t i = 0; i < count; i++) {
            packet_entry_t *pkt = batch[i];
            prepared_pcap_packet_t *prep = &prepared_packets[i];
            
            size_t total_len = pkt->caplen + 28;
            
            /* Build IP header */
            struct iphdr *ip = (struct iphdr *)prep->packet;
            ip->version = 4;
            ip->ihl = 5;
            ip->tos = 0;
            ip->tot_len = htons(total_len);
            ip->id = 0;
            ip->frag_off = 0;
            ip->ttl = 64;
            ip->protocol = IPPROTO_UDP;
            ip->check = 0;
            ip->saddr = pkt->src_addr.sin_addr.s_addr;
            ip->daddr = inet_addr(g_state.red_multicast_addr);
            
            /* Build UDP header */
            struct udphdr *udp = (struct udphdr *)(prep->packet + 20);
            udp->source = pkt->src_addr.sin_port;
            udp->dest = htons(g_state.red_port);
            udp->len = htons(pkt->caplen + 8);
            udp->check = 0;
            
            memcpy(prep->packet + 28, pkt->data, pkt->caplen);
            
            prep->phdr.ts_sec = pkt->ts.tv_sec;
            prep->phdr.ts_usec = pkt->ts.tv_usec;
            prep->phdr.incl_len = total_len;
            prep->phdr.orig_len = total_len;
            prep->packet_len = total_len;
            
            iov[iov_count].iov_base = &prep->phdr;
            iov[iov_count].iov_len = sizeof(pcap_packet_header_t);
            iov_count++;
            iov[iov_count].iov_base = prep->packet;
            iov[iov_count].iov_len = total_len;
            iov_count++;
        }
        
        if (writev(g_state.red_pcap_fd, iov, iov_count) < 0) {
            /* Silently ignore write errors - buffer will fill and drop packets */
        }
    }
    
    free(prepared_packets);
    return NULL;
}

/* Blue path writer thread - writes blue pcap file */
static void *blue_writer_thread_func(void *arg) {
    (void)arg;
    
    packet_entry_t *batch[WRITE_BATCH_SIZE];
    prepared_pcap_packet_t *prepared_packets = malloc(WRITE_BATCH_SIZE * sizeof(prepared_pcap_packet_t));
    
    if (!prepared_packets) {
        fprintf(stderr, "Error: Failed to allocate blue PCAP buffer\n");
        return NULL;
    }
    
    while (g_state.running || g_state.blue_ring->head != g_state.blue_ring->tail) {
        size_t count = ring_buffer_pop_batch(g_state.blue_ring, batch, WRITE_BATCH_SIZE);
        
        if (count == 0) {
            usleep(1000);
            continue;
        }
        
        /* Build and write PCAP packets */
        struct iovec iov[WRITE_BATCH_SIZE * 2];
        size_t iov_count = 0;
        
        for (size_t i = 0; i < count; i++) {
            packet_entry_t *pkt = batch[i];
            prepared_pcap_packet_t *prep = &prepared_packets[i];
            
            size_t total_len = pkt->caplen + 28;
            
            /* Build IP header */
            struct iphdr *ip = (struct iphdr *)prep->packet;
            ip->version = 4;
            ip->ihl = 5;
            ip->tos = 0;
            ip->tot_len = htons(total_len);
            ip->id = 0;
            ip->frag_off = 0;
            ip->ttl = 64;
            ip->protocol = IPPROTO_UDP;
            ip->check = 0;
            ip->saddr = pkt->src_addr.sin_addr.s_addr;
            ip->daddr = inet_addr(g_state.blue_multicast_addr);
            
            /* Build UDP header */
            struct udphdr *udp = (struct udphdr *)(prep->packet + 20);
            udp->source = pkt->src_addr.sin_port;
            udp->dest = htons(g_state.blue_port);
            udp->len = htons(pkt->caplen + 8);
            udp->check = 0;
            
            memcpy(prep->packet + 28, pkt->data, pkt->caplen);
            
            prep->phdr.ts_sec = pkt->ts.tv_sec;
            prep->phdr.ts_usec = pkt->ts.tv_usec;
            prep->phdr.incl_len = total_len;
            prep->phdr.orig_len = total_len;
            prep->packet_len = total_len;
            
            iov[iov_count].iov_base = &prep->phdr;
            iov[iov_count].iov_len = sizeof(pcap_packet_header_t);
            iov_count++;
            iov[iov_count].iov_base = prep->packet;
            iov[iov_count].iov_len = total_len;
            iov_count++;
        }
        
        if (writev(g_state.blue_pcap_fd, iov, iov_count) < 0) {
            /* Silently ignore write errors - buffer will fill and drop packets */
        }
    }
    
    free(prepared_packets);
    return NULL;
}

/* Writer thread - writes packets to file */
static void *writer_thread_func(void *arg) {
    (void)arg;
    
    packet_entry_t *batch[WRITE_BATCH_SIZE];
    prepared_pcap_packet_t *prepared_packets = NULL;
    
    /* Allocate prepared packet buffer for PCAP mode */
    if (g_state.pcap_mode) {
        prepared_packets = malloc(WRITE_BATCH_SIZE * sizeof(prepared_pcap_packet_t));
        if (!prepared_packets) {
            fprintf(stderr, "Error: Failed to allocate PCAP buffer\n");
            g_state.writer_done = true;
            return NULL;
        }
    }
    
    while (g_state.running || g_state.ring->head != g_state.ring->tail) {
        /* Batch pop for both modes */
        size_t count = ring_buffer_pop_batch(g_state.ring, batch, WRITE_BATCH_SIZE);
        
        if (count == 0) {
            /* Buffer empty, wait a bit */
            usleep(1000);  /* 1ms */
            continue;
        }
        
        /* Skip writing if no valid output fd */
        if (g_state.output_fd <= 0 && g_state.output_fd != STDOUT_FILENO) {
            continue;
        }
        
        /* Calculate total bytes for stats */
        size_t total_bytes = 0;
        for (size_t i = 0; i < count; i++) {
            total_bytes += batch[i]->caplen;
        }
        
        size_t written;
        if (g_state.pcap_mode) {
            /* PCAP mode: batch write with headers */
            written = write_pcap_batch(g_state.output_fd, batch, count, prepared_packets);
        } else {
            /* Raw mode: batch write payloads only */
            written = write_raw_batch(g_state.output_fd, batch, count);
        }
        
        if (written > 0) {
            __sync_fetch_and_add(&g_state.packets_written, count);
            __sync_fetch_and_add(&g_state.bytes_written, total_bytes);
        }
    }
    
    /* Cleanup */
    if (prepared_packets) {
        free(prepared_packets);
    }
    
    g_state.writer_done = true;
    return NULL;
}

/* Statistics thread - displays capture progress */
static void *stats_thread_func(void *arg) {
    (void)arg;
    
    if (g_state.quiet) return NULL;
    
    uint64_t last_bytes = 0;
    struct timeval last_time, now;
    gettimeofday(&last_time, NULL);
    
    while (g_state.running) {
        usleep(STATS_INTERVAL_MS * 1000);
        
        gettimeofday(&now, NULL);
        double elapsed = (now.tv_sec - last_time.tv_sec) + 
                        (now.tv_usec - last_time.tv_usec) / 1000000.0;
        
        uint64_t cur_bytes = g_state.bytes_captured;
        
        double mbps = ((cur_bytes - last_bytes) * 8.0) / (elapsed * 1000000.0);
        
        /* Calculate buffer fill based on mode */
        double fill;
        double red_fill = 0, blue_fill = 0;
        
        if (g_state.smpte2022_7) {
            red_fill = ring_buffer_fill_level(g_state.red_ring) * 100.0;
            blue_fill = ring_buffer_fill_level(g_state.blue_ring) * 100.0;
            /* Use max of red/blue for warning threshold */
            fill = (red_fill > blue_fill) ? red_fill : blue_fill;
        } else {
            fill = ring_buffer_fill_level(g_state.ring) * 100.0;
        }
        
        /* Determine warning level based on buffer fill */
        const char *warning = "";
        const char *color_start = "";
        const char *color_end = "";
        
        if (fill > 90.0 || g_state.packets_dropped > 0) {
            /* Critical - disk can't keep up */
            color_start = "\033[1;31m";  /* Bold red */
            color_end = "\033[0m";
            warning = " ** DISK TOO SLOW - DROPPING PACKETS **";
        } else if (fill > 75.0) {
            /* Warning - buffer filling up */
            color_start = "\033[1;33m";  /* Bold yellow */
            color_end = "\033[0m";
            warning = " * WARNING: Buffer filling - disk may be too slow *";
        } else if (fill > 50.0) {
            /* Caution */
            color_start = "\033[33m";  /* Yellow */
            color_end = "\033[0m";
            warning = " (buffer elevated)";
        }
        
        if (g_state.smpte2022_7) {
            /* SMPTE 2022-7 mode: show red/blue buffer levels */
            fprintf(stderr, "\r\033[K"
                    "\033[31mRed: %lu (%.1f%%)\033[0m | \033[34mBlue: %lu (%.1f%%)\033[0m | "
                    "%sDropped: %lu%s | %.1f Mbps%s",
                    g_state.red_packets, red_fill,
                    g_state.blue_packets, blue_fill,
                    g_state.packets_dropped > 0 ? "\033[1;31m" : "",
                    g_state.packets_dropped,
                    g_state.packets_dropped > 0 ? "\033[0m" : "",
                    mbps,
                    warning);
        } else {
            /* Single stream mode */
            fprintf(stderr, "\r\033[K"
                    "Captured: %lu | Written: %lu | %sDropped: %lu%s | "
                    "Rate: %.1f Mbps | Buffer: %s%.1f%%%s%s",
                    g_state.packets_captured,
                    g_state.packets_written,
                    g_state.packets_dropped > 0 ? "\033[1;31m" : "",
                    g_state.packets_dropped,
                    g_state.packets_dropped > 0 ? "\033[0m" : "",
                    mbps, 
                    color_start, fill, color_end,
                    warning);
        }
        
        last_bytes = cur_bytes;
        last_time = now;
    }
    
    fprintf(stderr, "\n");
    return NULL;
}

/* Print usage information */
static void print_usage(const char *prog) {
    fprintf(stderr, 
        "multicap v%s - High-performance multicast stream capture\n\n"
        "Usage: %s [OPTIONS]\n\n"
        "Single stream mode:\n"
        "  --multi, -m ADDR     Multicast group address (e.g., 239.1.1.1)\n"
        "  -i INTERFACE         Network interface (e.g., eth0, ens18)\n"
        "  --port, -p PORT      UDP port number\n"
        "  --pcap FILE          Write packets to PCAP file (use '-' for stdout)\n"
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
        "  --quiet, -q          Suppress statistics output\n"
        "  --version, -V        Show version information\n"
        "  --help, -h           Show this help message\n\n"
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
        MULTICAP_VERSION, prog, prog, prog, prog, prog);
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
        {0, 0, 0, 0}
    };
    
    g_state.buffer_mb = DEFAULT_BUFFER_MB;
    
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
            case 1001:  /* --redmulti */
                g_state.red_multicast_addr = optarg;
                break;
            case 1002:  /* --redport */
                g_state.red_port = atoi(optarg);
                break;
            case 1003:  /* --redint */
                g_state.red_interface = optarg;
                break;
            case 1004:  /* --bluemulti */
                g_state.blue_multicast_addr = optarg;
                break;
            case 1005:  /* --blueport */
                g_state.blue_port = atoi(optarg);
                break;
            case 1006:  /* --blueint */
                g_state.blue_interface = optarg;
                break;
            case 1007:  /* --redpcap */
                g_state.red_pcap_file = optarg;
                break;
            case 1008:  /* --bluepcap */
                g_state.blue_pcap_file = optarg;
                break;
            default:
                return -1;
        }
    }
    
    /* Validate required arguments based on mode */
    if (g_state.smpte2022_7) {
        /* SMPTE 2022-7 mode validation */
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
    } else {
        /* Single stream mode validation */
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
    }
    
    /* Validate output options based on mode */
    if (g_state.smpte2022_7) {
        /* In 2022-7 mode, need at least one pcap output */
        if (!g_state.red_pcap_file && !g_state.blue_pcap_file) {
            fprintf(stderr, "Error: At least one output required (--redpcap or --bluepcap)\n");
            return -1;
        }
    } else {
        /* Single stream mode requires --pcap or --raw */
        if (!g_state.output_file) {
            fprintf(stderr, "Error: Output file required (--pcap or --raw)\n");
            return -1;
        }
    }
    
    /* Validate multicast addresses */
    struct in_addr addr;
    
    if (g_state.smpte2022_7) {
        /* Validate red multicast address */
        if (inet_aton(g_state.red_multicast_addr, &addr) == 0) {
            fprintf(stderr, "Error: Invalid red path multicast address\n");
            return -1;
        }
        uint32_t ip = ntohl(addr.s_addr);
        if ((ip & 0xF0000000) != 0xE0000000) {
            fprintf(stderr, "Error: Red path address is not a multicast address\n");
            return -1;
        }
        
        /* Validate blue multicast address */
        if (inet_aton(g_state.blue_multicast_addr, &addr) == 0) {
            fprintf(stderr, "Error: Invalid blue path multicast address\n");
            return -1;
        }
        ip = ntohl(addr.s_addr);
        if ((ip & 0xF0000000) != 0xE0000000) {
            fprintf(stderr, "Error: Blue path address is not a multicast address\n");
            return -1;
        }
    } else {
        /* Validate single stream multicast address */
        if (inet_aton(g_state.multicast_addr, &addr) == 0) {
            fprintf(stderr, "Error: Invalid multicast address\n");
            return -1;
        }
        uint32_t ip = ntohl(addr.s_addr);
        if ((ip & 0xF0000000) != 0xE0000000) {
            fprintf(stderr, "Error: Address is not a multicast address (224.0.0.0 - 239.255.255.255)\n");
            return -1;
        }
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
    
    /* Enforce minimum */
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
    
    /* Auto-size: use 25% of free memory */
    return auto_mb;
}

int main(int argc, char **argv) {
    /* Parse arguments */
    if (parse_args(argc, argv) != 0) {
        print_usage(argv[0]);
        return 1;
    }
    
    /* Set up signal handlers */
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    signal(SIGPIPE, SIG_IGN);
    
    /* Calculate actual buffer size */
    g_state.buffer_mb = calculate_buffer_size(g_state.buffer_mb);
    
    /* Create ring buffer(s) based on mode */
    if (g_state.smpte2022_7) {
        /* SMPTE 2022-7 mode: only need 2 ring buffers (red, blue) */
        size_t per_buffer_mb = g_state.buffer_mb / 2;
        
        if (per_buffer_mb < MIN_BUFFER_MB) {
            per_buffer_mb = MIN_BUFFER_MB;
        }
        
        g_state.red_ring = ring_buffer_create(per_buffer_mb);
        g_state.blue_ring = ring_buffer_create(per_buffer_mb);
        
        if (!g_state.red_ring || !g_state.blue_ring) {
            fprintf(stderr, "Error: Failed to create ring buffers\n");
            if (g_state.red_ring) ring_buffer_destroy(g_state.red_ring);
            if (g_state.blue_ring) ring_buffer_destroy(g_state.blue_ring);
            return 1;
        }
        
        if (!g_state.quiet) {
            fprintf(stderr, "SMPTE 2022-7 mode: 2 x %zu MB ring buffers\n", per_buffer_mb);
        }
    } else {
        /* Single stream mode */
        g_state.ring = ring_buffer_create(g_state.buffer_mb);
        if (!g_state.ring) {
            fprintf(stderr, "Error: Failed to create ring buffer\n");
            return 1;
        }
        
        if (!g_state.quiet) {
            fprintf(stderr, "Ring buffer: %zu MB (%zu packet slots)\n", 
                    g_state.buffer_mb, g_state.ring->capacity);
        }
    }
    
    /* Open output file(s) based on mode */
    if (g_state.smpte2022_7) {
        /* SMPTE 2022-7 mode: no main output file, only red/blue pcaps (opened later) */
    } else {
        /* Single stream mode */
        if (strcmp(g_state.output_file, "-") == 0) {
            g_state.output_fp = stdout;
            g_state.output_fd = STDOUT_FILENO;
            g_state.quiet = true;  /* Don't mix stats with output */
        } else {
            g_state.output_fd = open(g_state.output_file, 
                                      O_WRONLY | O_CREAT | O_TRUNC, 
                                      0644);
            if (g_state.output_fd < 0) {
                perror("open");
                ring_buffer_destroy(g_state.ring);
                return 1;
            }
            g_state.output_fp = NULL;
        }
        
        /* Write PCAP header if in PCAP mode (single stream only) */
        if (g_state.pcap_mode) {
            pcap_file_header_t hdr = {
                .magic_number = PCAP_MAGIC,
                .version_major = PCAP_VERSION_MAJOR,
                .version_minor = PCAP_VERSION_MINOR,
                .thiszone = 0,
                .sigfigs = 0,
                .snaplen = MAX_PACKET_SIZE,
                .network = PCAP_LINKTYPE_RAW
            };
            if (write(g_state.output_fd, &hdr, sizeof(hdr)) != sizeof(hdr)) {
                fprintf(stderr, "Error: Failed to write PCAP header\n");
                close(g_state.output_fd);
                ring_buffer_destroy(g_state.ring);
                return 1;
            }
        }
    }
    
    /* Create multicast socket(s) based on mode */
    if (g_state.smpte2022_7) {
        /* Create red path socket */
        g_state.red_socket_fd = create_multicast_socket(g_state.red_multicast_addr, 
                                                         g_state.red_interface, 
                                                         g_state.red_port);
        if (g_state.red_socket_fd < 0) {
            fprintf(stderr, "Error: Failed to create red path socket\n");
            ring_buffer_destroy(g_state.red_ring);
            ring_buffer_destroy(g_state.blue_ring);
            return 1;
        }
        
        /* Create blue path socket */
        g_state.blue_socket_fd = create_multicast_socket(g_state.blue_multicast_addr, 
                                                          g_state.blue_interface, 
                                                          g_state.blue_port);
        if (g_state.blue_socket_fd < 0) {
            fprintf(stderr, "Error: Failed to create blue path socket\n");
            close(g_state.red_socket_fd);
            close(g_state.output_fd);
            ring_buffer_destroy(g_state.ring);
            ring_buffer_destroy(g_state.red_ring);
            ring_buffer_destroy(g_state.blue_ring);
            return 1;
        }
        
        /* Open red pcap file if specified */
        if (g_state.red_pcap_file) {
            g_state.red_pcap_fd = open(g_state.red_pcap_file, 
                                        O_WRONLY | O_CREAT | O_TRUNC, 0644);
            if (g_state.red_pcap_fd < 0) {
                perror("open red pcap");
                close(g_state.red_socket_fd);
                close(g_state.blue_socket_fd);
                close(g_state.output_fd);
                ring_buffer_destroy(g_state.ring);
                ring_buffer_destroy(g_state.red_ring);
                ring_buffer_destroy(g_state.blue_ring);
                return 1;
            }
            /* Write PCAP header */
            pcap_file_header_t hdr = {
                .magic_number = PCAP_MAGIC,
                .version_major = PCAP_VERSION_MAJOR,
                .version_minor = PCAP_VERSION_MINOR,
                .thiszone = 0,
                .sigfigs = 0,
                .snaplen = MAX_PACKET_SIZE,
                .network = PCAP_LINKTYPE_RAW
            };
            if (write(g_state.red_pcap_fd, &hdr, sizeof(hdr)) != sizeof(hdr)) {
                fprintf(stderr, "Error: Failed to write red PCAP header\n");
            }
        }
        
        /* Open blue pcap file if specified */
        if (g_state.blue_pcap_file) {
            g_state.blue_pcap_fd = open(g_state.blue_pcap_file, 
                                         O_WRONLY | O_CREAT | O_TRUNC, 0644);
            if (g_state.blue_pcap_fd < 0) {
                perror("open blue pcap");
                if (g_state.red_pcap_fd > 0) close(g_state.red_pcap_fd);
                close(g_state.red_socket_fd);
                close(g_state.blue_socket_fd);
                close(g_state.output_fd);
                ring_buffer_destroy(g_state.ring);
                ring_buffer_destroy(g_state.red_ring);
                ring_buffer_destroy(g_state.blue_ring);
                return 1;
            }
            /* Write PCAP header */
            pcap_file_header_t hdr = {
                .magic_number = PCAP_MAGIC,
                .version_major = PCAP_VERSION_MAJOR,
                .version_minor = PCAP_VERSION_MINOR,
                .thiszone = 0,
                .sigfigs = 0,
                .snaplen = MAX_PACKET_SIZE,
                .network = PCAP_LINKTYPE_RAW
            };
            if (write(g_state.blue_pcap_fd, &hdr, sizeof(hdr)) != sizeof(hdr)) {
                fprintf(stderr, "Error: Failed to write blue PCAP header\n");
            }
        }
        
        if (!g_state.quiet) {
            fprintf(stderr, "SMPTE 2022-7 Capture:\n");
            fprintf(stderr, "  Red:  %s:%d on %s", 
                    g_state.red_multicast_addr, g_state.red_port, g_state.red_interface);
            if (g_state.red_pcap_file) {
                fprintf(stderr, " -> %s", g_state.red_pcap_file);
            }
            fprintf(stderr, "\n");
            fprintf(stderr, "  Blue: %s:%d on %s", 
                    g_state.blue_multicast_addr, g_state.blue_port, g_state.blue_interface);
            if (g_state.blue_pcap_file) {
                fprintf(stderr, " -> %s", g_state.blue_pcap_file);
            }
            fprintf(stderr, "\n");
            if (g_state.duration_secs > 0) {
                fprintf(stderr, "  Duration: %d seconds\n", g_state.duration_secs);
            }
            fprintf(stderr, "Press Ctrl+C to stop capture\n\n");
        }
    } else {
        /* Single stream mode */
        g_state.socket_fd = create_multicast_socket(g_state.multicast_addr, 
                                                     g_state.interface, 
                                                     g_state.port);
        if (g_state.socket_fd < 0) {
            if (g_state.output_fd > 0 && g_state.output_fd != STDOUT_FILENO) {
                close(g_state.output_fd);
            }
            ring_buffer_destroy(g_state.ring);
            return 1;
        }
        
        if (!g_state.quiet) {
            fprintf(stderr, "Capturing %s:%d on %s -> %s (%s mode)\n",
                    g_state.multicast_addr, g_state.port, g_state.interface,
                    g_state.output_file,
                    g_state.pcap_mode ? "pcap" : "raw");
            if (g_state.duration_secs > 0) {
                fprintf(stderr, "Duration: %d seconds\n", g_state.duration_secs);
            }
            fprintf(stderr, "Press Ctrl+C to stop capture\n\n");
        }
    }
    
    /* Start threads based on mode */
    g_state.running = true;
    
    if (g_state.smpte2022_7) {
        /* SMPTE 2022-7 mode */
        pthread_create(&g_state.red_capture_thread, NULL, red_capture_thread_func, NULL);
        pthread_create(&g_state.blue_capture_thread, NULL, blue_capture_thread_func, NULL);
        
        /* Start red/blue writer threads if pcap files are specified */
        if (g_state.red_pcap_file) {
            pthread_create(&g_state.red_writer_thread, NULL, red_writer_thread_func, NULL);
        }
        if (g_state.blue_pcap_file) {
            pthread_create(&g_state.blue_writer_thread, NULL, blue_writer_thread_func, NULL);
        }
        
        pthread_create(&g_state.stats_thread, NULL, stats_thread_func, NULL);
        
        /* Wait for capture threads to complete */
        pthread_join(g_state.red_capture_thread, NULL);
        pthread_join(g_state.blue_capture_thread, NULL);
        
        /* Wait for red/blue writers to finish */
        if (g_state.red_pcap_file) {
            pthread_join(g_state.red_writer_thread, NULL);
        }
        if (g_state.blue_pcap_file) {
            pthread_join(g_state.blue_writer_thread, NULL);
        }
        
        pthread_join(g_state.stats_thread, NULL);
    } else {
        /* Single stream mode */
        pthread_create(&g_state.capture_thread, NULL, capture_thread_func, NULL);
        pthread_create(&g_state.writer_thread, NULL, writer_thread_func, NULL);
        pthread_create(&g_state.stats_thread, NULL, stats_thread_func, NULL);
        
        /* Wait for capture to complete */
        pthread_join(g_state.capture_thread, NULL);
        
        /* Signal writer to finish remaining packets */
        pthread_cond_broadcast(&g_state.ring->not_empty);
        pthread_join(g_state.writer_thread, NULL);
        pthread_join(g_state.stats_thread, NULL);
    }
    
    /* Print final statistics */
    if (!g_state.quiet) {
        fprintf(stderr, "\nCapture complete:\n");
        if (g_state.smpte2022_7) {
            fprintf(stderr, "  Red path packets:   %lu\n", g_state.red_packets);
            fprintf(stderr, "  Blue path packets:  %lu\n", g_state.blue_packets);
        } else {
            fprintf(stderr, "  Packets captured:   %lu\n", g_state.packets_captured);
            fprintf(stderr, "  Packets written:    %lu\n", g_state.packets_written);
        }
        fprintf(stderr, "  Packets dropped:    %lu\n", g_state.packets_dropped);
        fprintf(stderr, "  Bytes captured:     %lu (%.2f MB)\n", 
                g_state.bytes_captured, g_state.bytes_captured / (1024.0 * 1024.0));
        if (g_state.packets_dropped > 0) {
            fprintf(stderr, "  Drop rate:          %.2f%%\n",
                    100.0 * g_state.packets_dropped / 
                    (g_state.red_packets + g_state.blue_packets + g_state.packets_dropped));
        }
    }
    
    /* Cleanup */
    if (g_state.smpte2022_7) {
        close(g_state.red_socket_fd);
        close(g_state.blue_socket_fd);
        if (g_state.red_pcap_fd > 0) close(g_state.red_pcap_fd);
        if (g_state.blue_pcap_fd > 0) close(g_state.blue_pcap_fd);
        ring_buffer_destroy(g_state.red_ring);
        ring_buffer_destroy(g_state.blue_ring);
    } else {
        close(g_state.socket_fd);
    }
    
    if (g_state.output_fp && g_state.output_fp != stdout) {
        fclose(g_state.output_fp);
    } else if (g_state.output_fd > 0 && g_state.output_fd != STDOUT_FILENO) {
        close(g_state.output_fd);
    }
    ring_buffer_destroy(g_state.ring);
    
    return (g_state.packets_dropped > 0) ? 2 : 0;
}
