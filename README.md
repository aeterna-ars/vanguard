# Vanguard

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Rust](https://img.shields.io/badge/rust-1.70%2B-blue.svg)](https://www.rust-lang.org/)

**Vanguard** is a high-performance, Rust-based XDP (eXpress Data Path) filtering and load-balancing utility. It is designed to operate at the network driver level, providing an ultra-fast, programmable packet processing layer for modern cloud and edge infrastructures.

Inspired by the architectural principles of Facebook's **Katran** and Cloudflare's **Unimog**, Vanguard aims to bring the power of eBPF and XDP to the Rust ecosystem, offering a memory-safe, highly efficient, and extensible platform for network telemetry, security, and traffic management.

## Philosophy

Vanguard is built on the idea that the most critical network functions—filtering, load balancing, and DDoS protection—should be handled before they even reach the kernel's network stack. By leveraging the XDP hook, Vanguard can process packets at line rate, making it an ideal first line of defense or a high-performance load balancer for L3/L4 traffic.

In the spirit of projects like **Katran**, Vanguard focuses on:
- **Performance:** Bypassing the traditional kernel stack to achieve millions of packets per second (PPS) on commodity hardware.
- **Programmability:** Allowing users to define complex, stateful packet filtering and forwarding policies using a modern Rust eBPF framework.
- **Observability:** Providing deep insights into packet flows, drops, and redirections through eBPF maps and ring buffers.

## Key Features

- **XDP-Based Packet Processing:** Attach programs directly to network interfaces for low-latency, high-throughput packet inspection and manipulation.
- **Rust & Aya Framework:** Entirely written in Rust using the **Aya** library, ensuring memory safety and seamless integration with the eBPF ecosystem without external C dependencies.
- **Stateful Filtering:** Implements a dynamic blocklist with support for time-based bans and rate limiting.
- **Advanced Rule Engine:** Allows for the definition of fine-grained rules based on IP, protocol, and ports, including actions like `PASS`, `DROP`, `TX`, and `REDIRECT`.
- **Performance-Oriented Data Structures:** Utilizes `LruPerCpuHashMap` for lock-free, per-CPU counters, maximizing performance under high loads.
- **Rapid Development:** The core logic is concise, making it easy to understand, customize, and extend.

## Project Status

🚧 **Work in Progress (WIP)** 🚧

Vanguard is under active development. The core XDP filtering and rate-limiting functionality is being implemented. The goal is to create a production-ready tool that can be used as a foundation for high-performance network services.

## Getting Started

(To be added: instructions for building and running Vanguard using `cargo` and `bpftool`.)

## Inspiration & Acknowledgements

Vanguard is deeply inspired by the groundbreaking work done on:

- **[Katran](https://github.com/facebookincubator/katran):** Facebook's high-performance L4 load balancer.
- **[Unimog](https://blog.cloudflare.com/unimog-cloudflares-edge-load-balancer/):** Cloudflare's edge load balancer technology.

These projects have demonstrated the immense potential of XDP and eBPF for building scalable, efficient network services. Vanguard aims to bring these capabilities to the Rust ecosystem, fostering a new wave of innovation in network programming.

## License

This project is licensed under the GPL-2.0 License - see the [LICENSE](LICENSE) file for details.

---
