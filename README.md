# Multithreaded TCP Packet Sniffer and TCP Header Analyzer

## Overview
Information travels across networks in the form of data packets. Early or single-threaded packet sniffing tools often create a "traffic jam" when capturing, parsing, and analyzing packets sequentially on one thread.

This project implements a multithreaded C++ TCP packet sniffer built over `libpcap` that decouples live packet capture from packet inspection and logging using a producer-consumer pipeline[cite: 1, 5]. It captures raw network frames, filters for IPv4 TCP traffic (`ether_type == 0x0800` and `ip->protocol == 6`), decodes Ethernet, IPv4, and TCP headers, maps decoded fields to exact raw byte offsets, prints hex dumps, and writes structured records to `tcp_analysis.csv`[cite: 1, 2, 3, 5].

---

## Core Features & Capabilities

### 1. Interactive Interface Discovery & Selection
* Enumerates available network interfaces dynamically at runtime using `pcap_findalldevs()`, displaying interface names and descriptions so users do not have to hardcode or memorize interface flags[cite: 5].
* Opens the selected interface via `pcap_open_live()` for live packet capture[cite: 1, 4].

### 2. Multithreaded Producer-Consumer Architecture (`CircularRingBuffer`)
* **Producer (`pcap_loop` callback):** Captures incoming frames from `libpcap` and pushes copies (`pcap_pkthdr` + raw packet bytes) into a bounded `CircularRingBuffer` (1,024 slots in `PacketSniffer`)[cite: 1, 5].
* **Consumer (`processPacketsLoop` worker thread):** Pulls items from the ring buffer using `std::mutex` and `std::condition_variable` synchronization and passes them to `TCPPacketAnalyzer`[cite: 1, 5].
* **Bounded Memory & Drop Safety:** Caps queue growth to a fixed slot ceiling to prevent unbounded memory growth during traffic spikes, safely rejecting/dropping excess packets when full[cite: 1, 5].

### 3. Safe Header Parsing & Boundary Guards
* Uses `#pragma pack(push, 1)` on `EthernetHeader`, `IPHeader`, and `TCPHeader` structs so binary packet fields align directly with wire byte layouts without compiler padding[cite: 1, 5].
* Enforces `header->caplen` checks at each layer and computes dynamic IP (`(ver_ihl & 0x0F) * 4`) and TCP (`((data_offset_reserved >> 4) & 0x0F) * 4`) header lengths to prevent out-of-bounds reads on truncated or malformed frames.
* Filters early to process IPv4 (`0x0800`) and TCP (`protocol == 6`) packets while safely skipping non-TCP/malformed frames without crashing.

### 4. TCP Header Inspection & Raw Byte-to-Field Mapping
* Extracts and converts network-to-host byte order (`ntohs` / `ntohl`) for:
  * Source and destination IPv4 addresses (via `inet_ntop`) and TCP ports.
  * 32-bit sequence and acknowledgment numbers.
  * TCP header length, window size, and hex checksum.
  * All six TCP control flags (`URG`, `ACK`, `PSH`, `RST`, `SYN`, `FIN`).
* Maps decoded values back to exact raw byte ranges in the captured frame (e.g., source/destination IP bytes, source/destination port bytes, sequence/acknowledgment bytes, and TCP flags byte) and prints formatted hex slices alongside a full raw hex dump.

### 5. Structured CSV Logging & Filtering/Sorting Workflow
* Logs analyzed TCP packet telemetry to `tcp_analysis.csv` with immediate per-packet flushing (`csvFile.flush()`) so records are persisted in real time.
* Supports post-capture or export workflows for saving captured traffic to log/capture files and filtering or sorting records by user-defined criteria.

---

## Benchmark Summary (vs. Scapy, tcpdump & Wireshark)
Evaluated on an Ubuntu 24.04 testbed (8-core x86_64 @ 3.6 GHz, 16 GB RAM, `veth` interface with `tcpreplay`)[cite: 3]:
* **Throughput:** Reached ~82k pps sustained (82% capture on a 5,000-packet / 15 ms micro-burst), outperforming Python Scapy (~8.5k pps), while `tcpdump` achieved >240k pps lossless capture.
* **Latency:** Averaged **11.4 µs/packet** (10.4× faster than Scapy's 118.5 µs/packet; compared to 3.8 µs for `tcpdump` and 14.2 µs for Wireshark).
* **Memory & CPU:** Used **14.2 MB RSS** and **44% CPU across 2 threads**—95% less RAM than Wireshark (312 MB) and well below Scapy (68.5 MB at 99% single-core GIL saturation).
* **Accuracy & Safety:** Achieved **100% header accuracy** on test sessions and zero crashes on truncated, IPv6 (`0x86DD`), UDP, or invalid-IHL frames.

---

## Known Limitations & Planned Enhancements

### Current Limitations
* **Stateless per-packet analysis:** Inspects packets individually rather than reassembling TCP streams, computing RTT, or tracking retransmissions.
* **Synchronous I/O & console overhead:** Per-packet console hex printing and `csvFile.flush()` throttle sustained consumer throughput above ~82,000 pps during heavy bursts.
* **Scope of protocol & layer dissection:** Focuses on IPv4 TCP headers and raw L7 hex rather than full TCP options parsing, application-layer (L7) protocol decoding, or UDP/ICMP/IPv6 handling.

### Future Scope & Optimizations
* Attach a compiled kernel BPF `"tcp"` filter via `pcap_compile()` and `pcap_setfilter()` in `startSniffing()` so non-TCP frames are filtered before entering user space.
* Replace per-packet `flush()` calls with buffered batch I/O and expand `CircularRingBuffer` (e.g., to 16,384 slots with pre-reserved capacity) to reduce burst drops and heap reallocations.
* Extend protocol support (UDP, ICMP, IPv6), TCP options decoding, stateful flow/stream tracking, and richer filtering/sorting options.

---

## Build & Run
* **Dependencies:** C++17 (or later) compiler with `<thread>`, `<mutex>`, and `<condition_variable>`, plus `libpcap` development headers (`libpcap-dev` on Debian/Ubuntu).
* **Privileges:** Root or `CAP_NET_RAW` / `CAP_NET_ADMIN` privileges are typically required to open live network interfaces for packet capture.
