# multicap

High-performance multicast stream capture utility for Linux.

Designed to capture high-bitrate multicast streams (>1.5 Gbps) without dropping packets, using a threaded architecture with a large ring buffer to decouple network I/O from disk I/O.

## Features

- **High Performance**: Separate threads for capture and writing with lock-free ring buffer
- **PCAP Output**: Write standard PCAP files compatible with Wireshark, tcpdump, etc.
- **Raw Output**: Strip IP/UDP/RTP headers and write raw payload (e.g., MPEG-TS streams)
- **Adaptive Buffer**: Automatically uses up to 25% of free RAM for the ring buffer
- **Real-time Statistics**: Live display of packets captured, written, dropped, and buffer health
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

```bash
multicap [OPTIONS]

Required options:
  --multi, -m ADDR     Multicast group address (e.g., 239.1.1.1)
  -i INTERFACE         Network interface (e.g., eth0, ens18)
  --port, -p PORT      UDP port number

Output options (one required):
  --pcap FILE          Write packets to PCAP file (use '-' for stdout)
  --raw FILE           Write raw payload to file (use '-' for stdout)
                       Automatically strips RTP headers if present

Optional:
  --duration, -d SECS  Capture duration in seconds (0 = unlimited)
  --buffer, -b MB      Ring buffer size in MB (default: auto, up to 25% of free RAM)
  --quiet, -q          Suppress statistics output
  --help, -h           Show help message
```

## Examples

### Capture to PCAP file
```bash
# Capture multicast stream to PCAP file
multicap --multi 239.1.1.1 -i eth0 --port 5000 --pcap capture.pcap

# Capture for 60 seconds
multicap --multi 239.1.1.1 -i eth0 --port 5000 --pcap capture.pcap -d 60

# Override auto buffer size (e.g., limit to 256 MB)
multicap --multi 239.1.1.1 -i eth0 --port 5000 --pcap capture.pcap -b 256
```

### Capture raw MPEG-TS stream
```bash
# Capture raw payload (RTP headers automatically stripped)
multicap --multi 239.1.1.1 -i eth0 --port 5000 --raw stream.ts
```

### Pipe to analysis tools
```bash
# Pipe to tcpdump for live analysis
multicap --multi 239.1.1.1 -i eth0 --port 5000 --pcap - | tcpdump -r - -nn

# Pipe to Wireshark's tshark
multicap --multi 239.1.1.1 -i eth0 --port 5000 --pcap - | tshark -r -

# Pipe raw TS to ffprobe
multicap --multi 239.1.1.1 -i eth0 --port 5000 --raw - | ffprobe -i -
```

## Architecture

```
┌─────────────────┐      ┌─────────────────┐      ┌─────────────────┐
│  Network Card   │ ───▶ │  Capture Thread │ ───▶ │   Ring Buffer   │
│  (multicast rx) │      │  (high priority)│      │ (mmap'd memory) │
└─────────────────┘      └─────────────────┘      └────────┬────────┘
                                                           │
                                                           ▼
┌─────────────────┐      ┌─────────────────┐      ┌─────────────────┐
│   Output File   │ ◀─── │  Writer Thread  │ ◀─── │    Pop Entry    │
│  (pcap or raw)  │      │ (buffered I/O)  │      │                 │
└─────────────────┘      └─────────────────┘      └─────────────────┘

┌─────────────────┐
│  Stats Thread   │ ───▶ stderr (live statistics)
└─────────────────┘
```

### Key Design Decisions

1. **Separate Threads**: Network capture runs in a high-priority thread to minimize dropped packets. Writing runs in a separate thread so disk I/O doesn't block capture.

2. **Ring Buffer**: Large memory-mapped ring buffer decouples capture from writing. Sized to handle burst scenarios where disk can't keep up temporarily.

3. **Lock-Free Push**: The capture thread uses lock-free operations for pushing packets, with memory barriers for correctness.

4. **Large Socket Buffer**: Requests a 64MB kernel socket buffer to handle bursts before they reach userspace.

5. **Buffered File I/O**: Uses 1MB file buffer for efficient disk writes.

## Performance Tuning

For best results with high-bitrate streams (>1 Gbps):

### 1. System Socket Buffers
```bash
# Increase maximum socket buffer size
sudo sysctl -w net.core.rmem_max=536870912
sudo sysctl -w net.core.rmem_default=67108864

# Make permanent in /etc/sysctl.conf
echo "net.core.rmem_max=536870912" | sudo tee -a /etc/sysctl.conf
echo "net.core.rmem_default=67108864" | sudo tee -a /etc/sysctl.conf
```

### 2. Network Interface
```bash
# Increase NIC ring buffer
sudo ethtool -G eth0 rx 4096

# Check current settings
ethtool -g eth0
```

### 3. Disk I/O
- Use SSD or NVMe storage for output files
- Consider writing to a RAM disk (`/dev/shm`) for short captures
- Use a dedicated disk for capture output

### 4. Capabilities (instead of running as root)
```bash
# Grant network and scheduling capabilities
sudo setcap cap_net_raw,cap_net_admin,cap_sys_nice+ep /usr/local/bin/multicap
```

### 5. CPU Affinity
```bash
# Pin to specific CPU cores (less context switching)
taskset -c 2,3 multicap --multi 239.1.1.1 -i eth0 --port 5000 --pcap out.pcap

# NUMA-aware for multi-socket systems
numactl --cpunodebind=0 --membind=0 multicap ...
```

## Statistics Display

During capture, multicap shows live statistics:

```
Captured: 1234567 pkts | Written: 1234500 pkts | Dropped: 0 pkts | Rate: 1523.4 Mbps (125000 pps) | Buffer: 2.3%
```

- **Captured**: Packets received from network
- **Written**: Packets written to output file
- **Dropped**: Packets lost due to full buffer
- **Rate**: Current capture rate in Mbps and packets per second
- **Buffer**: Ring buffer fill percentage (warning if >75%)

## Exit Codes

- `0`: Success, no packets dropped
- `1`: Error (invalid arguments, socket error, etc.)
- `2`: Success, but some packets were dropped

## Requirements

- Linux kernel 2.6.32+ (for mmap features)
- GCC with C99 support
- pthread library
- Root privileges or appropriate capabilities for:
  - Joining multicast groups
  - Binding to interfaces
  - Real-time thread scheduling

## License

MIT License - feel free to use, modify, and distribute.

## Troubleshooting

### "Address is not a multicast address"
Multicast addresses must be in the range 224.0.0.0 - 239.255.255.255.

### "Interface not found"
Check interface name with `ip link show` or `ifconfig`.

### "Could not bind to interface (need root?)"
Run as root or set capabilities. The tool will still work but may receive traffic from other interfaces.

### High packet drop rate
1. Check disk I/O with `iostat`
2. Increase buffer size with `-b`
3. Apply system tuning (see above)
4. Use faster storage

### No packets captured
1. Verify multicast traffic exists: `tcpdump -i eth0 host 239.1.1.1`
2. Check firewall rules: `sudo iptables -L`
3. Verify interface is correct and up
