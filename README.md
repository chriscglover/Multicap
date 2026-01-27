# multicap

High-performance multicast stream capture utility for Linux.

Version 2.0

Designed to capture high-bitrate multicast streams (>1.5 Gbps) without dropping packets, using a threaded architecture with large ring buffers to decouple network I/O from disk I/O. Supports SMPTE 2022-7 seamless protection switching with simultaneous capture of both redundant paths.

## Features

- **High Performance**: Separate threads for capture and writing with lock-free ring buffer
- **PCAP Output**: Write standard PCAP files compatible with Wireshark, tcpdump, etc.
- **Raw Output**: Strip IP/UDP/RTP headers and write raw payload (e.g., MPEG-TS streams)
- **SMPTE 2022-7 Support**: Capture both red and blue redundant paths simultaneously
- **Adaptive Buffer**: Automatically uses up to 25% of free RAM for ring buffers
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
  --pcap FILE          Write packets to PCAP file (use '-' for stdout)
  --raw FILE           Write raw payload to file (strips RTP headers)

Optional:
  --duration, -d SECS  Capture duration in seconds (0 = unlimited)
  --buffer, -b MB      Ring buffer size in MB (default: auto)
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
  --buffer, -b MB      Ring buffer size in MB (default: auto)
  --quiet, -q          Suppress statistics output
```

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
┌─────────────────┐      ┌─────────────────┐      ┌─────────────────┐
│  Network Card   │ ───▶ │  Capture Thread │ ───▶ │   Ring Buffer   │
│  (multicast rx) │      │  (high priority)│      │ (mmap'd memory) │
└─────────────────┘      └─────────────────┘      └────────┬────────┘
                                                           │
                                                           ▼
┌─────────────────┐      ┌─────────────────┐      ┌─────────────────┐
│   Output File   │ ◀─── │  Writer Thread  │ ◀─── │  Batch writev() │
│  (pcap or raw)  │      │                 │      │                 │
└─────────────────┘      └─────────────────┘      └─────────────────┘
```

### SMPTE 2022-7 Mode

```
┌──────────────┐    ┌──────────────┐    ┌──────────────┐    ┌──────────────┐
│   Red NIC    │───▶│ Red Capture  │───▶│  Red Ring    │───▶│ Red Writer   │───▶ red.pcap
└──────────────┘    └──────────────┘    └──────────────┘    └──────────────┘

┌──────────────┐    ┌──────────────┐    ┌──────────────┐    ┌──────────────┐
│  Blue NIC    │───▶│ Blue Capture │───▶│  Blue Ring   │───▶│ Blue Writer  │───▶ blue.pcap
└──────────────┘    └──────────────┘    └──────────────┘    └──────────────┘

                    ┌──────────────┐
                    │ Stats Thread │───▶ stderr (live statistics)
                    └──────────────┘
```

### Key Design Decisions

1. **Separate Threads**: Network capture runs in high-priority threads to minimize dropped packets. Writing runs in separate threads so disk I/O doesn't block capture.

2. **Ring Buffers**: Large memory-mapped ring buffers decouple capture from writing. Sized to handle burst scenarios where disk can't keep up temporarily.

3. **Lock-Free Push**: Capture threads use lock-free operations for pushing packets, with memory barriers for correctness.

4. **Batch Writing**: Uses `writev()` to write up to 256 packets per system call, dramatically reducing syscall overhead.

5. **Large Socket Buffer**: Requests a 64MB kernel socket buffer to handle bursts before they reach userspace.

## Statistics Display

### Single Stream Mode
```
Captured: 1234567 | Written: 1234500 | Dropped: 0 | Rate: 1523.4 Mbps | Buffer: 2.3%
```

### SMPTE 2022-7 Mode
```
Red: 617283 (1.2%) | Blue: 617284 (1.1%) | Dropped: 0 | 3046.8 Mbps
```

Buffer fill warnings:
- **>50%**: Yellow "(buffer elevated)"
- **>75%**: Bold yellow "WARNING: Buffer filling"
- **>90%**: Bold red "DISK TOO SLOW - DROPPING PACKETS"

## Performance Tuning

For best results with high-bitrate streams (>1 Gbps):

### System Socket Buffers
```bash
sudo sysctl -w net.core.rmem_max=536870912
sudo sysctl -w net.core.rmem_default=67108864
```

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
```bash
sudo setcap cap_net_raw,cap_net_admin,cap_sys_nice+ep /usr/local/bin/multicap
```

## Exit Codes

- `0`: Success, no packets dropped
- `1`: Error (invalid arguments, socket error, etc.)
- `2`: Success, but some packets were dropped

## Requirements

- Linux kernel 2.6.32+
- GCC with C99 support
- pthread library
- Root privileges or appropriate capabilities

## Version History

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

### High packet drop rate
1. Check disk speed - use RAM disk for testing
2. Increase buffer size with `-b`
3. Apply system tuning (see above)
4. Use NVMe storage for 3+ Gbps streams

### No packets captured
1. Verify multicast traffic: `tcpdump -i eth0 host 239.1.1.1`
2. Check firewall rules: `sudo iptables -L`
3. Verify interface is correct and up
