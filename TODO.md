# TODO

Future enhancements for multicap.

## RDMA / Kernel Bypass Support

For capturing streams beyond 3 Gbps, kernel bypass is essential to avoid packet drops.

### Options to Investigate

#### 1. ibverbs (Verbs API)
- Direct access to RDMA-capable NICs
- Works with Mellanox ConnectX and Intel E810/X722
- Most control, best performance
- Requires significant refactoring of receive path

#### 2. DPDK (Data Plane Development Kit)
- Mature mlx5 PMD for Mellanox NICs
- Can handle 100 Gbps+ line rate
- Polls NIC directly in userspace
- Would require DPDK as a build dependency

#### 3. AF_XDP (eXpress Data Path)
- Newer Linux kernel feature (4.18+)
- Less invasive than full DPDK
- Keeps some kernel integration
- Good middle ground between socket API and full bypass

### Implementation Notes
- Keep existing socket-based capture as fallback/default
- Add `--rdma` or `--dpdk` flag to enable kernel bypass
- Ring buffer architecture remains the same
- Need to handle NIC-specific setup (hugepages, permissions, etc.)

### Reference Hardware
- Mellanox ConnectX-5/6 (excellent DPDK and ibverbs support)
- Intel E810 (good AF_XDP and DPDK support)
- Intel X710/X722 (DPDK support)

### Testing Targets
- 10 Gbps SMPTE 2110
- 25 Gbps aggregated streams
- 100 Gbps with DPDK

## Completed in v2.0

- [x] Basic multicast capture
- [x] PCAP output
- [x] Raw payload output with RTP stripping
- [x] Threaded architecture with ring buffer
- [x] Auto-sizing buffer (25% of free RAM)
- [x] Live statistics display
- [x] Duration-limited capture
- [x] Batch I/O with writev()
- [x] SMPTE 2022-7 redundant path capture
- [x] Man page
