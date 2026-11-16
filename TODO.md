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

## Possible follow-ups

- `--raw` keeps v2.0's MPEG-TS sync-byte search, which can trim up to 16 bytes
  from non-TS payloads (e.g. ST 2022-6) when the data happens to contain 0x47
  patterns. Make it apply only to MPEG-TS payloads (RTP PT 33).
- `--raw` for 2022-7 mode.
- `PACKET_FANOUT` across several capture threads for >10 Gbps on one path.
- Restore the NIC hardware timestamp setting on SIGKILL too (currently on
  normal exit only).

## Completed in v3.0

- [x] AF_PACKET + TPACKET_V3 mmap receive; real Ethernet frames in pcap
- [x] Kernel BPF filter (group + port), IGMP join on a separate socket
- [x] Nanosecond pcap timestamps; optional hardware timestamps (`--hwts`)
- [x] VLAN tag restore
- [x] GRO aggregate handling (`--split-gro`, raw mode)
- [x] Kernel ring drop statistics
- [x] Variable-length ring records; writer/capture race fixed
- [x] One code path for single, red and blue

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
