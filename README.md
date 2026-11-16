# multicap

High-performance multicast stream capture utility for Linux.

Version 3.0

Designed to capture high-bitrate multicast streams (>1.5 Gbps) without dropping packets, using a threaded architecture with large ring buffers to decouple network I/O from disk I/O. Supports SMPTE 2022-7 seamless protection switching with simultaneous capture of both redundant paths.

Since 3.0, multicap receives with an `AF_PACKET` `TPACKET_V3` memory-mapped ring, so its pcap files hold the **real Ethernet frames from the wire**: MAC addresses, VLAN tag, IP header (TTL, DSCP, ID, flags, checksum) and UDP header exactly as received, with nanosecond timestamps. They open fully in Wireshark (eth / vlan / ip / udp / rtp) and match a `tcpdump -w` of the same group frame for frame.

It is NIC-agnostic: it uses only standard Linux packet-socket interfaces and works on any Ethernet driver (Intel, Mellanox/NVIDIA, Broadcom, virtio, ...). Optional features such as hardware timestamps fall back cleanly when a driver does not support them.

## Features

- **Real wire frames**: `LINKTYPE_ETHERNET` pcap, every header as received; nothing is synthesised
- **Nanosecond timestamps**: kernel (or, with `--hwts`, NIC hardware) receive time, written as nanosecond pcap
- **Kernel-side filter**: a classic BPF filter (`udp and dst host GROUP and dst port PORT`) runs before frames reach the ring, so other traffic on the NIC costs almost nothing
- **VLAN tags restored**: if the NIC strips the 802.1Q tag, it is put back in the frame written to the pcap
- **GRO aware**: aggregates the kernel builds from several datagrams are recognised; `--split-gro` turns them back into one frame per datagram, and `--raw` always handles them per datagram
- **Separate drop counters**: kernel ring drops (capture CPU too slow) and userspace ring drops (output too slow) are reported separately
- **High Performance**: Separate threads for capture and writing with a lock-free single-producer/single-consumer ring (C11 atomics)
- **PCAP Output**: Write standard PCAP files compatible with Wireshark, tcpdump, etc.
- **Raw Output**: Strip IP/UDP/RTP headers and write raw payload (e.g., MPEG-TS streams)
- **SMPTE 2022-7 Support**: Capture both red and blue redundant paths simultaneously
- **Adaptive Buffer**: Automatically uses up to 25% of free RAM for ring buffers; variable-length records, so small and jumbo frames both use only the space they need
- **Batch I/O**: Uses `writev()` to batch multiple packets per system call
- **Real-time Statistics**: Live display of packets captured, dropped, and buffer health
- **Duration Control**: Capture for a specified number of seconds
- **Stdout Support**: Pipe PCAP output directly to analysis tools

## Building

```bash
# Build optimized release binary
make

# Build debug binary
make debug

# Install to /usr/local/bin (or PREFIX=/path)
sudo make install
```

## Usage

### Single Stream Mode

```bash
multicap [OPTIONS]

Required:
  --multi, -m ADDR     Multicast group address (e.g., 239.1.1.1)
  -i INTERFACE         Network interface (e.g., eth0, ens18)
  --port, -p PORT      UDP port number

Output (one required):
  --pcap FILE          Write Ethernet frames to PCAP file (use '-' for stdout)
  --raw FILE           Write raw payload to file (strips RTP headers)

Optional:
  --duration, -d SECS  Capture duration in seconds (0 = unlimited)
  --buffer, -b MB      Ring buffer size in MB (default: auto)
  --kring MB           Kernel receive ring per path in MB (default: 256)
  --split-gro          Write each datagram of a GRO aggregate as its own frame
  --hwts               Use NIC hardware receive timestamps if available
  --quiet, -q          Suppress statistics output
  --version, -V        Show version information
  --help, -h           Show help message
```

### SMPTE 2022-7 Mode

```bash
multicap -7 [OPTIONS]

Required:
  --redmulti ADDR      Red path multicast address
  --redport PORT       Red path UDP port
  --redint INTERFACE   Red path network interface
  --bluemulti ADDR     Blue path multicast address
  --blueport PORT      Blue path UDP port
  --blueint INTERFACE  Blue path network interface

Output (at least one required):
  --redpcap FILE       Write red path to PCAP file
  --bluepcap FILE      Write blue path to PCAP file

Optional:
  --duration, -d SECS  Capture duration in seconds (0 = unlimited)
  --buffer, -b MB      Ring buffer size in MB, shared by the paths (default: auto)
  --kring MB           Kernel receive ring per path in MB (default: 256)
  --split-gro          Write each datagram of a GRO aggregate as its own frame
  --hwts               Use NIC hardware receive timestamps if available
  --quiet, -q          Suppress statistics output
```

A path without an output file (e.g. no `--bluepcap`) is not captured and does not join its group.

## Examples

### Single Stream Capture

```bash
# Capture multicast stream to PCAP file
multicap --multi 239.1.1.1 -i eth0 --port 5000 --pcap capture.pcap

# Capture for 60 seconds
multicap --multi 239.1.1.1 -i eth0 --port 5000 --pcap capture.pcap -d 60

# Capture raw MPEG-TS stream (RTP headers stripped)
multicap --multi 239.1.1.1 -i eth0 --port 5000 --raw stream.ts

# Pipe to tcpdump for live analysis
multicap --multi 239.1.1.1 -i eth0 --port 5000 --pcap - | tcpdump -r - -nn

# One pcap record per datagram even where the NIC/kernel aggregates (GRO)
multicap --multi 239.1.1.1 -i eth0 --port 5000 --pcap capture.pcap --split-gro

# NIC hardware timestamps where the card supports them
multicap --multi 239.1.1.1 -i eth0 --port 5000 --pcap capture.pcap --hwts
```

### SMPTE 2022-7 Capture

```bash
# Capture both redundant paths
multicap -7 \
  --redmulti 239.20.1.35 --redport 40000 --redint eth20 --redpcap red.pcap \
  --bluemulti 239.21.1.35 --blueport 40000 --blueint eth21 --bluepcap blue.pcap

# Capture for 30 seconds
multicap -7 -d 30 \
  --redmulti 239.20.1.35 --redport 40000 --redint eth20 --redpcap red.pcap \
  --bluemulti 239.21.1.35 --blueport 40000 --blueint eth21 --bluepcap blue.pcap

# Capture only red path
multicap -7 \
  --redmulti 239.20.1.35 --redport 40000 --redint eth20 --redpcap red.pcap \
  --bluemulti 239.21.1.35 --blueport 40000 --blueint eth21
```

## Architecture

### Single Stream Mode

```
┌──────────────┐   ┌──────────────┐   ┌──────────────┐   ┌──────────────┐
│ Network Card │──▶│  Kernel BPF  │──▶│ TPACKET_V3   │──▶│Capture Thread│
│              │   │ (group:port) │   │ mmap RX ring │   │(high priority)│
└──────────────┘   └──────────────┘   └──────────────┘   └──────┬───────┘
                                                                │ copy frame,
                                                                │ restore VLAN tag
                                                                ▼
┌──────────────┐   ┌──────────────┐   ┌─────────────────────────────────┐
│ Output File  │◀──│Writer Thread │◀──│ Userspace ring (variable-length │
│ (pcap or raw)│   │ batch writev │   │ records, sized from free RAM)   │
└──────────────┘   └──────────────┘   └─────────────────────────────────┘

┌──────────────┐
│ UDP socket   │  holds the IGMP membership only (drop-all filter, never read)
└──────────────┘
```

### SMPTE 2022-7 Mode

Each path (red, blue) is an independent copy of the pipeline above, with its own packet socket, kernel ring, userspace ring, writer and statistics; one stats thread reports on both.

```
Red NIC  ──▶ BPF ──▶ Red kernel ring  ──▶ Red capture  ──▶ Red ring  ──▶ Red writer  ──▶ red.pcap
Blue NIC ──▶ BPF ──▶ Blue kernel ring ──▶ Blue capture ──▶ Blue ring ──▶ Blue writer ──▶ blue.pcap
                                        Stats thread ──▶ stderr (live statistics)
```

### Key Design Decisions

1. **AF_PACKET + TPACKET_V3**: Receiving below the IP stack keeps the Ethernet, IP and UDP headers. The filter and ring are attached before the socket is bound to the interface, so no unfiltered frame ever reaches the ring.

2. **Two rings**: The kernel ring (`--kring`, default 256 MB per path in 4 MB blocks) absorbs scheduling hiccups of the capture thread; frames are copied straight out of it into the large userspace ring, which absorbs disk stalls. Nothing is written to disk from the kernel ring.

3. **Lock-free ring**: One capture thread produces and one writer consumes, using C11 acquire/release atomics. The writer releases space only after the data has been written, so a nearly full ring can never overwrite packets still being written.

4. **Zero-copy writes**: Each ring record stores the pcap record header next to the frame, so the writer hands frames to `writev()` straight from the ring, up to 1024 per call.

5. **IGMP join socket**: An ordinary UDP socket joins the group on the chosen interface so the switch keeps forwarding the stream. It is never bound or read, and carries a drop-everything filter and a tiny buffer, so it costs nothing.

6. **Per-path design**: Single mode, red and blue all use the same capture and writer code.

## GRO (Generic Receive Offload)

Many NICs and drivers (and virtual NICs) merge consecutive UDP datagrams of a stream into one large "aggregate" before the packet socket sees it; on a ST 2022-6 stream that is typically 46 x 1400-byte datagrams in one 64 KB frame. `tcpdump` records these aggregates as they are, and so does `multicap --pcap` by default, so its files match `tcpdump` exactly. In Wireshark such a record shows only the first RTP header.

- `--split-gro` writes each datagram of an aggregate as its own frame: the Ethernet/IP/UDP headers are copied from the aggregate with the lengths, IP ID (+1 per datagram) and IP/UDP checksums recomputed for each datagram, which is what the kernel itself does when it splits such a packet. All datagrams of one aggregate carry its timestamp.
- `--raw` always splits aggregates, so its output is the same as with GRO off.
- The segment size comes from the kernel (`PACKET_VNET_HDR`), which needs Linux 6.2 or later. On older kernels aggregates are written as received and counted in the summary; turn GRO off on a dedicated capture NIC (`ethtool -K eth0 gro off`) if you need per-datagram frames there.

The summary shows how many frames were aggregates and how many UDP datagrams they carried.

## Statistics Display

### Single Stream Mode
```
Captured: 1234567 | Written: 1234500 | Ring drops: 0 | Kernel drops: 0 | Rate: 1523.4 Mbps | Buffer: 2.3%
```

### SMPTE 2022-7 Mode
```
Red: 617283 (1.2%) | Blue: 617284 (1.1%) | Ring drops: 0 | Kernel drops: 0 | 3046.8 Mbps
```

Counts are frames (a GRO aggregate is one frame; the summary also gives UDP datagrams).

- **Ring drops**: the userspace ring was full; the output (disk, pipe) is too slow.
- **Kernel drops**: the kernel ring was full; the capture thread did not keep up (CPU starved). Read with `PACKET_STATISTICS`. Try a bigger `--kring`, CPU isolation or `cap_sys_nice`.

Buffer fill warnings:
- **>50%**: Yellow "(buffer elevated)"
- **>75%**: Bold yellow "WARNING: Buffer filling"
- **>90%** or any ring drop: Bold red "DISK TOO SLOW - DROPPING PACKETS"
- Any kernel drop: Bold red "KERNEL RING DROPS - capture CPU too slow"

The summary at the end lists, per path, frames captured and written, UDP datagrams, both drop counts, bytes, drop rate and (with `--hwts`) how many frames carried a hardware timestamp.

## Performance Tuning

For best results with high-bitrate streams (>1 Gbps):

### Kernel Ring
The kernel receive ring is set with `--kring` (default 256 MB per path, about 400 ms at 5 Gbps). The `net.core.rmem_*` socket buffer sysctls no longer matter: frames do not pass through a socket buffer.

### Network Interface
```bash
# Increase NIC ring buffer
sudo ethtool -G eth0 rx 4096
```

### Disk I/O
- Use NVMe SSD for >1.5 Gbps streams
- Use RAM disk (`/dev/shm` or `tmpfs`) for short captures at 3+ Gbps
- Avoid SATA SSDs for sustained 3+ Gbps capture

### Capabilities (instead of root)
multicap needs `CAP_NET_RAW` to open the packet socket. The usual setcap line grants it:
```bash
sudo setcap cap_net_raw,cap_net_admin,cap_sys_nice+ep /usr/local/bin/multicap
```
- `cap_net_raw`: required (packet socket)
- `cap_net_admin`: for `--hwts` (enable hardware timestamping on the NIC)
- `cap_sys_nice`: real-time priority for the capture thread
- `cap_ipc_lock` (optional): lets the large ring be locked in RAM

File capabilities are ignored on filesystems mounted `nosuid` (often `/tmp`).

### Hardware Timestamps (`--hwts`)
multicap asks the NIC to timestamp all received packets (`SIOCSHWTSTAMP`, `HWTSTAMP_FILTER_ALL`) and restores the previous setting on exit. Drivers that cannot do this (many virtual NICs, some older Intel parts) are reported and software timestamps are used. Hardware timestamps come from the NIC's PTP clock, so they are only comparable with system time if that clock is synchronised (e.g. `phc2sys`).

## Exit Codes

- `0`: Success, no packets dropped
- `1`: Error (invalid arguments, socket error, etc.)
- `2`: Success, but some packets were dropped

## Requirements

- Linux kernel 3.2+ (TPACKET_V3); 6.2+ to split GRO aggregates
- GCC with C11 support
- pthread library
- Root, or `CAP_NET_RAW` (see Capabilities)
- Any Ethernet NIC and driver

## Version History

### 3.0 (2026-11-16)
- Receives with AF_PACKET + TPACKET_V3 mmap ring: pcap files hold the real Ethernet frames (LINKTYPE_ETHERNET) instead of synthesised IP/UDP headers
- Nanosecond pcap timestamps from the kernel; optional NIC hardware timestamps (`--hwts`)
- Kernel BPF filter on group and port; fixes v2.0 capturing every group joined on the same port by any program on the host (Linux `IP_MULTICAST_ALL`)
- VLAN tags restored when the NIC strips them
- GRO aggregates recognised; `--split-gro`; `--raw` splits them so output is unchanged
- Kernel ring drops reported separately from userspace ring drops; `--kring`
- Variable-length ring records (a 512 MB ring held only ~8k packets in 2.0)
- Fixed ring race: the writer could have slots overwritten while still writing them
- Fixed drop rate in single mode, and 2022-7 per-path statistics (written count, orig_len)
- Write errors reported; a closed output pipe ends the capture cleanly
- Single capture/writer implementation for single, red and blue paths

### 2.0 (2026-01-28)
- Added SMPTE 2022-7 seamless protection switching support
- Separate capture of red and blue redundant paths
- Batch I/O with writev() for improved performance
- Per-path ring buffers and writer threads
- Color-coded buffer warnings

### 1.0
- Initial release
- Single stream capture
- PCAP and raw output modes

## License

MIT License - Copyright (c) 2026 Christopher Glover

## Troubleshooting

### "Address is not a multicast address"
Multicast addresses must be in the range 224.0.0.0 - 239.255.255.255.

### "Interface not found"
Check interface name with `ip link show`.

### "Operation not permitted" / "needs CAP_NET_RAW"
Run as root or set capabilities (see above). Check the binary is not on a `nosuid` filesystem.

### High packet drop rate
1. **Ring drops**: check disk speed - use RAM disk for testing; increase buffer size with `-b`; use NVMe storage for 3+ Gbps streams
2. **Kernel drops**: increase `--kring`, give the capture thread a quiet CPU, grant `cap_sys_nice`
3. Apply system tuning (see above)

### Wireshark shows huge "lost" RTP counts or 64 KB UDP packets
The NIC has GRO on and the records are aggregates. Capture with `--split-gro` (see GRO above).

### No packets captured
1. Verify multicast traffic: `tcpdump -i eth0 host 239.1.1.1`
2. Verify interface is correct and up
3. Check the switch sees the IGMP join (multicap joins on the `-i` interface). Firewall rules and `rp_filter` do not affect capture, as frames are taken before the IP stack.
