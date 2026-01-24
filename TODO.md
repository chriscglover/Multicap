# TODO

Future enhancements for multicap.

## High Priority

### RDMA / Kernel Bypass Support
For capturing streams beyond 3 Gbps, kernel bypass is essential to avoid packet drops.

**Options to investigate:**

1. **ibverbs (Verbs API)**
   - Direct access to RDMA-capable NICs
   - Works with Mellanox ConnectX and Intel E810/X722
   - Most control, best performance
   - Requires significant refactoring of receive path

2. **DPDK (Data Plane Development Kit)**
   - Mature mlx5 PMD for Mellanox NICs
   - Can handle 100 Gbps+ line rate
   - Polls NIC directly in userspace
   - Would require DPDK as a build dependency

3. **AF_XDP (eXpress Data Path)**
   - Newer Linux kernel feature (4.18+)
   - Less invasive than full DPDK
   - Keeps some kernel integration
   - Good middle ground between socket API and full bypass

**Implementation notes:**
- Keep existing socket-based capture as fallback/default
- Add `--rdma` or `--dpdk` flag to enable kernel bypass
- Ring buffer architecture remains the same
- Need to handle NIC-specific setup (hugepages, permissions, etc.)

## Medium Priority

### Packet Filtering
- Filter by source IP address
- Filter by SSRC (RTP synchronization source)
- BPF-style filter expressions

### Multiple Stream Capture
- Join multiple multicast groups simultaneously
- Write to separate output files or interleaved with markers
- Useful for capturing primary + backup streams

### Statistics Improvements
- Per-second min/max/avg packet rates
- Histogram of packet sizes
- Inter-packet arrival time jitter measurement
- Export stats to JSON file

### SMPTE 2022-7 Seamless Protection Switching
Capture both paths of redundant streams with proper network separation.

**Requirements:**
- Separate NIC per path (red/blue network separation)
- Example: Rohde & Schwarz Prismon, Nevion Virtuoso, etc.

**Proposed CLI:**
```bash
multicap \
  --stream red:239.1.1.1:eth0:5000 \
  --stream blue:239.1.2.1:eth1:5000 \
  --smpte2022-7 --raw output.ts
```

**Implementation:**
- Two capture threads (one per NIC)
- Separate socket and ring buffer per path
- Merge thread that:
  - Matches packets by RTP sequence number
  - Implements 2022-7 delay buffer for timing differences
  - Reconstructs single output filling gaps from either path
- Handle sequence number wraparound (16-bit)

**Output options:**
- Combined reconstructed stream (`--raw output.ts`)
- Separate pcaps per path (`--pcap-red red.pcap --pcap-blue blue.pcap`)
- Switchover event log (`--report switchovers.json`)
  - Timestamp of each gap/recovery
  - Which path was used for each packet
  - Overall path reliability stats

## Low Priority

### Output Formats
- Native Wireshark pcapng format (more metadata)
- Raw payload with sidecar timestamp file
- Direct write to network storage (NFS, iSCSI)

### Configuration File
- YAML/JSON config file for complex setups
- Multiple capture profiles
- Preset system tuning recommendations

### GUI / Web Interface
- Real-time stats dashboard
- Start/stop capture remotely
- Buffer and throughput graphs

### Systemd Integration
- Service file for running as daemon
- Socket activation
- Journal logging

## Completed
- [x] Basic multicast capture
- [x] PCAP output
- [x] Raw payload output with RTP stripping
- [x] Threaded architecture with ring buffer
- [x] Auto-sizing buffer (25% of free RAM)
- [x] Live statistics display
- [x] Duration-limited capture
- [x] Man page

## Notes

### Testing Targets
- 1.5 Gbps SMPTE 2022-6 (HD-SDI)
- 3 Gbps SMPTE 2022-6 (3G-SDI)
- 10 Gbps+ with RDMA/DPDK

### Reference Hardware
- Mellanox ConnectX-5/6 (excellent DPDK and ibverbs support)
- Intel E810 (good AF_XDP and DPDK support)
- Intel X710/X722 (DPDK support)
