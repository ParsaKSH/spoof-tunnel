# Spoof Tunnel
[Persian-فارسی](README-fa.md)

Spoof Tunnel is a Layer 3/Layer 4 tunneling proxy designed to bypass Deep Packet Inspection (DPI) and strict stateful firewalls through **mutual bidirectional IP spoofing**.

Unlike traditional tunneling protocols that establish a stateful connection between a fixed client IP and a fixed server IP, Spoof Tunnel completely decouples the logical session from the physical network addresses by forging the `Source IP` field in the IP header at both endpoints.

> [!IMPORTANT]
> Both your servers must be able to send spoofed packets.
>
> To test this, you can use the following command temporarily on any of your servers:
>
> iptables -t nat -A POSTROUTING -d target-ip -j SNAT --to-source spoof-ip
>
> then:
>
> ping target-ip
>
> and use a tool like tcpdump on the opposite server:
>
> tcpdump icmp
>
> if you see the spoofed packets, means your source side can send spoofed packets.
>
> You can also use the much more accurate **spoof-tester** tool built into the core and panel. (It is highly recommended to use it before configuring your tunnel.)

### How the Project Came to Be: The Origin of Spoof Tunnel
The concept of a bidirectional spoofing tunnel emerged in response to the severe internet blackout in Iran following the bloody uprising on January 8 and 9, 2026 (18-19 Dey 1404). During this complete disconnection from the global internet, our primary objective was to reverse-engineer the exact scope and layer of the imposed restrictions.

Upon investigating the BGP routes for Iranian IP prefixes, we observed a surprising detail: unlike the internet shutdown in Afghanistan where BGP routes simply disappeared, Iran's IP ranges were still actively being announced globally. This strongly indicated that the international physical infrastructure was still intact.

Subsequently, it became apparent that certain government-affiliated Iranian entities were able to whitelist their specific IP addresses, successfully restoring their international connectivity. This observation led to the hypothesis that the restriction was being enforced at Layer 3, specifically filtering based on srcIP and dstIP.

This hypothesis was definitively confirmed when we discovered that a select few foreign IP addresses (such as specific ranges from Hetzner) could still establish inbound connections to Iran. The evidence clearly demonstrated that the "blackout" was not a physical severance, but rather a stringent, whitelist-based Layer 3 firewall policy.

In this highly restricted environment, the idea of a spoofing tunnel was conceived. By manipulating the IP headers, we could simulate whitelisted traffic. However, as is inherent to IP spoofing, if a spoofed packet is sent to a server, the server will inherently route its reply back to the spoofed IP address—not the actual origin host.

Therefore, a standard unidirectional spoof was insufficient. We required a robust bidirectional mutual spoofing mechanism where both the client and the server forge their IP headers and are predetermined instances well-aware of each other's actual physical IPs, enabling them to establish and maintain a logical connection despite the asymmetrical, forged routing.

## Quick Install (Tunnel Core + GUI Panel):
```bash
bash <(curl -Ls https://raw.githubusercontent.com/ParsaKSH/spoof-tunnel/main/panel/install.sh)
```

## 1. Core Architecture: Mutual IP Spoofing

### 1.1 Asymmetric Data Flow
In a typical scenario, the client and server agree on specific IP addresses to spoof:

* **Client → Server (Upload):** The client transmits packets with a forged source IP (e.g., `Client_Spoof_IP`) addressed to the server's actual listening IP.
* **Server → Client (Download):** The server responds by transmitting packets with a forged source IP (e.g., `Server_Spoof_IP`) addressed to the client's actual IP.

This creates a scenario where intermediate firewalls see unidirectional flows that do not logically match any active state mappings, effectively bypassing connection tracking tables (conntrack) and traffic fingerprinting.

### 1.2 Raw Socket Implementation
To inject packets with arbitrarily modified Layer 3 headers, Spoof Tunnel utilizes raw sockets (`AF_INET`, `SOCK_RAW`). It constructs the entire IPv4/IPv6 header manually, calculating the corresponding IP checksums in software.

* `gopacket` and `pcap` are heavily utilized to bypass the host kernel's network stack.
* **BPF Filters:** To prevent the host OS from dropping inbound spoofed packets or responding with `ICMP Destination Unreachable` / `TCP RST`, an aggressive Berkeley Packet Filter (BPF) limits the capture scope strictly to the tunnel's expected flow, bypassing local routing limits.

## 2. Supported Transports

### 2.1 ICMP (Echo Mode)
The tunnel encapsulates encrypted chunks inside standard `ICMP Echo Request (Type 8)` and `ICMP Echo Reply (Type 0)` packets. To network middleboxes, the traffic appears as benign ping sweeps or monitoring traffic.

### 2.2 ICMPv6 Mode
In addition to ICMP, ICMPv6 is also supported. Since firewalls that fully block IPv6 infrastructure tend to place fewer restrictions on the ICMPv6 protocol itself, you can carry your payload using the ICMPv6 protocol number over IPv4.

### 2.3 UDP Mode
Standard UDP datagrams are utilized with dynamically shiftable source ports. The protocol mimics connectionless DNS or custom UDP application patterns.

### 2.4 TCP (SYN flag) Mode
In addition to the other three protocols, plain TCP is supported. During heavy censorship events, the Iranian firewall tends to block UDP and most other protocols first — TCP is typically the last protocol to be fully shut down.

---
<details>
<summary>📌 v1.0.3 Features (Deprecated)</summary>

## 3. The Reliability Layer
Because ICMP and UDP provide no delivery guarantees, Spoof Tunnel implements a custom TCP-like reliability layer in user space. This is mandatory for maintaining stable TLS handshakes and in-order stream delivery.

* **Packet Sequencing and ACKs:** Every payload packet is wrapped in a `SeqDataPacket` format containing a monotonic sequence number (4 bytes). The recipient acknowledges data via `AckPacket`, utilizing a 64-bit acknowledgment bitmap for handling blocks of data efficiently.
* **Flow Control & Buffers:** The `RecvBuffer` maintains an internal map of sequences. Out-of-order packets are buffered and data is strictly delivered to the target socket *in-order*.
* **Retransmission Engine:** An active background goroutine sweeps the `SendBuffer` every 100ms. Unacknowledged packets exceeding the `retransmit_timeout` are resent using exponential backoff up to a defined `max_retries` limit.

## 4. Session Multiplexing
Establishing a new tunnel session incurs significant latency. To mitigate this, Spoof Tunnel implements an internal multiplexer (Mux).

A single "Master Session" is established over the unreliable link. All incoming local TCP SOCKS5 connections are assigned a virtual 4-byte `StreamID` and multiplexed within this single master session.

* `0x01 MuxStreamOpen:` Followed by [StreamID:4][TargetLen:2][Target String]
* `0x02 MuxStreamData:` Followed by [StreamID:4][Raw Payload]
* `0x03 MuxStreamClose:` Followed by [StreamID:4]
* `0x04 MuxStreamAck:` Server acknowledgment for successful proxy stream creation.

## 5. Cryptography
Security and obfuscation are enforced via **ChaCha20-Poly1305 AEAD**. AEAD ensures that not a single byte of the IP payload or tunnel header structure is visible or modifiable by an active MITM attacker without immediately dropping the connection.

Each session initializes a randomized nonce mechanism to prevent replay attacks, while the static pre-shared Base64 keys act as the master cryptographic secret.
</details>

---

<details>
<summary>📌 v3+ Features</summary>

## 6. Asymmetric Transport Protocols

Each client or server can independently choose a different transport protocol for each direction. For example, the client sends via TCP while the server responds via ICMPv6. Choose based on your specific server's censorship constraints.

## 7. Simple UDP-Pipe

Starting from v2, to improve performance and reduce processing overhead, the core has been refactored into a simple UDP pipe. It listens on a UDP port; you send any UDP traffic to it, the core tunnels the packet to the server, and on the server side it forwards to any endpoint you configure.

As a result, features like FEC, ChaCha20 crypto, SOCKS, ACK/TCP-like system, etc. have been removed from the core.

The recommended approach is to create a local IPv4/IPv6 tunnel using WireGuard.
You can refer to this WireGuard local IPv6 setup script:
`https://github.com/ParsaKSH/TAQ-BOSTAN/blob/main/wireguard.sh`

On the client side, set the `endpoint` in `/etc/wireguard/TAQBOSTANwg.conf` to `127.0.0.1` and the port the client core is listening on. An MTU of 1280 is recommended.

## 8. Spoof IP List Support

Starting from v3, instead of a single spoof IP, you can provide a list of IPs. The core will cycle through them in round-robin order, using a new IP from the list for each outgoing packet.

The reason for this feature: the infrastructure firewall may enforce bandwidth or volume limits on whitelisted IPs. Using a single IP means its limits directly degrade your tunnel quality.

To learn how to find valid spoof IPs, see the Spoof Tester section below.

## 9. Low-Level Modules Rewritten in Rust

Starting from v2, the high-load parts of the core responsible for packet-level processing and IP header manipulation have been rewritten in Rust for minimum CPU overhead and maximum performance.

## 10. Built-in Spoof Packet Tester & IP Discovery Tool

### 10.1 Supported Transports: ICMP & TCP

The tester module currently supports two protocols — TCP and ICMP — which you can choose based on your needs.

### 10.2 IP Range Input Support

You can provide individual IPs or IP ranges to test which ones can be used for spoofing. The module expands the ranges and sends spoofed packets from each IP individually.
The receiver side waits for packets and records any that arrive successfully.

**Supported input formats:**
- Single IP → `192.168.1.1`
- IP range → `192.168.1.1-192.168.1.255`
- CIDR range → `192.168.1.0/24`

### 10.3 Configurable Packet Loss Threshold

You can specify the maximum acceptable packet loss percentage per spoof IP on each side.

### 10.4 Sender & Receiver Modes

This module requires two servers (nodes) — one acts as **sender**, the other as **receiver**.

**How to use:**
1. Set the client (Iran server) to **sender** mode. Configure: protocol, IP range file, target IP (foreign server), attempts per IP, max allowed packet loss, and timeout.
2. Set the server (foreign server) to **receiver** mode with the same settings.
3. Start the **receiver** first, then immediately start the **sender**.
4. After the timeout, the receiver will have a list of IPs whose spoofed packets arrived, along with each IP's packet loss rate.
5. Repeat the process in **reverse** — client becomes receiver, server becomes sender.
6. If both servers support spoofing, you'll have a list of valid spoof IPs for each direction.

> **Important:** The output of the client in receiver mode should be used as the spoof IP list on the **server** side, and vice versa.

</details>

---

<details>
<summary>📌 Web GUI Panel</summary>

Starting from v2, a web management panel is included for ease of use. Install it using the install script at:
`https://github.com/ParsaKSH/spoof-tunnel/blob/main/panel/install.sh`

On Iran-based servers, you may need to run the script steps manually.

All core features — including the tunnel instances and the tester module — are fully accessible through the panel.

<p align="center">
  <img alt="image" src="https://github.com/user-attachments/assets/38296eb4-aaf8-4fef-a3ba-f8f6d3978c6b" width="48%" />
  <img width="48%" alt="image" src="https://github.com/user-attachments/assets/81dabbae-3a14-4b35-aa81-c895b80444fe" />
  <img width="48%" alt="image" src="https://github.com/user-attachments/assets/13970857-57d9-42bf-b738-4ad86de14787" />
</p>
</details>

---

<details>
<summary>📌 v1.0.3 (Deprecated) — Usage Guide</summary>

## Usage Instructions

### 1. Build the Binary
Spoof Tunnel is written in Go. You can build it using the standard Go toolchain:

```bash
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags="-s -w" -o spoof ./cmd/spoof/
```

### 2. Generate Cryptographic Keys
Before starting the tunnel, generate a pair of Base64 private/public keys for both the server and the client.

```bash
./spoof keygen
```
*Take note of the Private Key and Public Key.* The Server's Public Key must be placed in the Client's `peer_public_key` field, and vice versa.

### 3. Running the Service
> **Note:** Raw sockets require elevated privileges. You must execute both binaries as `root` (or assign the `CAP_NET_RAW` capability).

**On the Server:**
```bash
sudo ./spoof -c server-config.json
```

**On the Client:**
```bash
sudo ./spoof -c client-config.json
```
Once connected, the client opens a SOCKS5 proxy on `127.0.0.1:1080` (by default) that routes all traffic through the spoofed tunnel.

---

## Client Config (v1)

| Section | Key | Type | Description |
|---|---|---|---|
| mode | mode | string | Must be "client" |
| transport | type | string | "udp" or "icmp" |
| transport | icmp_mode | string | "echo" or "reply" (ICMP only) |
| transport | protocol_number | int | 0 (default, unused for ICMP/UDP) |
| listen | address | string | SOCKS5 listening address (e.g. 127.0.0.1) |
| listen | port | int | SOCKS5 listening port (e.g. 1080) |
| server | address | string | Remote server actual IP |
| server | port | int | Remote server port (for UDP) |
| spoof | source_ip | string | IP this client claims when sending outbound packets |
| spoof | peer_spoof_ip | string | Expected spoofed source IP of incoming server packets |
| crypto | private_key | string | Client's Base64 private key |
| crypto | peer_public_key | string | Server's Base64 public key |
| performance | buffer_size | int | Main packet buffer size |
| performance | mtu | int | Max payload before encapsulation (e.g. 1400) |
| performance | session_timeout | int | Master session timeout (seconds) |
| performance | workers | int | Number of packet processing goroutines |
| performance | read_buffer | int | Kernel socket read buffer size |
| performance | write_buffer | int | Kernel socket write buffer size |
| fec | enabled | bool | Enable Reed-Solomon Forward Error Correction |
| fec | data_shards | int | Number of data shards |
| fec | parity_shards | int | Number of parity shards |
| logging | level | string | "info", "debug", "warn", or "error" |
| logging | file | string | Log file path (empty = stdout) |

## Server Config (v1)

| Section | Key | Type | Description |
|---|---|---|---|
| mode | mode | string | Must be "server" |
| transport | type | string | "udp" or "icmp" |
| transport | icmp_mode | string | "echo" or "reply" (ICMP only) |
| transport | protocol_number | int | 0 (default) |
| listen | address | string | Tunnel listening IP (e.g. 0.0.0.0) |
| listen | port | int | UDP listening port (ignored for ICMP) |
| spoof | source_ip | string | IP this server claims when sending outbound packets |
| spoof | source_ipv6 | string | IPv6 version of source_ip |
| spoof | peer_spoof_ip | string | Expected spoofed source IP of incoming client packets |
| spoof | peer_spoof_ipv6 | string | IPv6 version of peer_spoof_ip |
| spoof | client_real_ip | string | Client's actual real IP |
| spoof | client_real_ipv6 | string | IPv6 version of client_real_ip |
| crypto | private_key | string | Server's Base64 private key |
| crypto | peer_public_key | string | Client's Base64 public key |
| performance | buffer_size | int | Main packet buffer size |
| performance | mtu | int | Max payload before encapsulation |
| performance | session_timeout | int | Master session timeout (seconds) |
| performance | workers | int | Number of packet processing goroutines |
| performance | read_buffer | int | Kernel socket read buffer size |
| performance | write_buffer | int | Kernel socket write buffer size |
| reliability | enabled | bool | Enable custom TCP-like reliability layer |
| reliability | window_size | int | Max unacknowledged packets in flight |
| reliability | retransmit_timeout_ms | int | Base retransmission timeout (ms) |
| reliability | max_retries | int | Max retransmission attempts per packet |
| reliability | ack_interval_ms | int | How often to send ACKs (ms) |
| fec | enabled | bool | Enable Reed-Solomon Forward Error Correction |
| fec | data_shards | int | Number of data shards |
| fec | parity_shards | int | Number of parity shards |
| keepalive | enabled | bool | Enable periodic keepalive pings |
| keepalive | interval_seconds | int | Seconds between keepalive packets |
| keepalive | timeout_seconds | int | Session drop timeout if no activity |
| logging | level | string | "info", "debug", "warn", or "error" |
| logging | file | string | Log file path (empty = stdout) |

</details>

---

<details>
<summary>📌 v3+ Usage Guide</summary>

## Usage Instructions

Spoof Tunnel is developed in both Go and Rust. To build from source yourself (instead of using GitHub Actions releases), you need both compilers installed.

Clone the repository:
```bash
git clone --depth=1 https://github.com/ParsaKSH/spoof-tunnel.git
```

Enter the project directory:
```bash
cd spoof-tunnel
```

Build using make:
```bash
make core
```

To build both the panel and the core (requires Node.js and npm):
```bash
make all
```

> **Note:** Building manually is not required — you can use pre-built releases from GitHub.

## Client (Local) Config

| Key | Type | Description |
|---|---|---|
| mode | string | Role of the core: client or server (`local`) |
| listen | string | UDP endpoint the local core listens on (e.g. `127.0.0.1:5000`) — send your traffic here |
| remote | string | Server IP (foreign server) |
| remote_port | int | Port the server listens on (for UDP/TCP) |
| recv_port | int | Port the client listens on (for TCP/UDP) |
| spoof-ip | string | Single spoof IP (use if not using a list) |
| spoof-ip-file | string | Path to spoof IP list file (use instead of single IP) |
| spoof-port | int | Source port placed in outgoing packets (for TCP/UDP) |
| send-transport | string | Transport the client uses to send packets (ICMP/ICMPv6/TCP/UDP) |
| recv-transport | string | Transport the server uses to send packets back (ICMP/ICMPv6/TCP/UDP) |

---

## Server (Remote) Config

| Key | Type | Description |
|---|---|---|
| mode | string | Role of the core: client or server (`remote`) |
| forward | string | Endpoint to forward received traffic to (e.g. `127.0.0.1:51820`) |
| client_ip | string | Client IP (Iran server) |
| client_port | int | Port the client listens on (for UDP/TCP) |
| listen_port | int | Port the server listens on to receive client packets (for TCP/UDP) |
| spoof-ip | string | Single spoof IP (use if not using a list) |
| spoof-ip-file | string | Path to spoof IP list file (use instead of single IP) |
| spoof-port | int | Source port placed in outgoing packets (for TCP/UDP) |
| send-transport | string | Transport the server uses to send packets (ICMP/ICMPv6/TCP/UDP) |
| recv-transport | string | Transport the client uses to send packets to the server (ICMP/ICMPv6/TCP/UDP) |

All config parameters can be provided either in a JSON file and run with `./spoof run -c config.json`, or as command-line flags:

```bash
./spoof remote --forward 127.0.0.1:51820 --spoof-ip-file /path/to/src.txt ...
```

</details>

---

Developed and tested during the complete Iranian internet blackout following the bloody uprising on 18 and 19 Dey (January 8–9, 2026).