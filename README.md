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
> if you see the spoofed packets, means your source side can send spoofed packet.

### How the Project Came to Be: The Origin of Spoof Tunnel
The concept of a bidirectional spoofing tunnel emerged in response to the severe internet blackout in Iran following the bloody uprising on January 8 and 9, 2026 (18-19 Dey 1404). During this complete disconnection from the global internet, our primary objective was to reverse-engineer the exact scope and layer of the imposed restrictions.

Upon investigating the BGP routes for Iranian IP prefixes, we observed a surprising detail: unlike the internet shutdown in Afghanistan where BGP routes simply disappeared, Iran's IP ranges were still actively being announced globally. This strongly indicated that the international physical infrastructure was still intact.

Subsequently, it became apparent that certain government-affiliated Iranian entities were able to whitelist their specific IP addresses, successfully restoring their international connectivity. This observation led to the hypothesis that the restriction was being enforced at Layer 3, specifically filtering based on srcIP and dstIP.

This hypothesis was definitively confirmed when we discovered that a select few foreign IP addresses (such as specific ranges from Hetzner) could still establish inbound connections to Iran. The evidence clearly demonstrated that the "blackout" was not a physical severance, but rather a stringent, whitelist-based Layer 3 firewall policy.

In this highly restricted environment, the idea of a spoofing tunnel was conceived. By manipulating the IP headers, we could simulate whitelisted traffic. However, as is inherent to IP spoofing, if a spoofed packet is sent to a server, the server will inherently route its reply back to the spoofed IP address—not the actual origin host.

Therefore, a standard unidirectional spoof was insufficient. We required a robust bidirectional mutual spoofing mechanism where both the client and the server forge their IP headers and are predetermined instances well-aware of each other's actual physical IPs, enabling them to establish and maintain a logical connection despite the asymmetrical, forged routing.


## 1. Core Architecture: Mutual IP Spoofing

### 1.1 Asymmetric Data Flow
In a typical scenario, the client and server agree on specific IP addresses to spoof:

* **Client → Server (Upload):** The client transmits packets with a forged source IP (e.g., `Client_Spoof_IP`) addressed to the server's actual listening IP.
* **Server → Client (Download):** The server responds by transmitting packets with a forged source IP (e.g., `Server_Spoof_IP`) addressed to the client's actual IP.

This creates a scenario where intermediate firewalls see unidirectional UDP or ICMP flows that do not logically match any active state mappings, effectively bypassing connection tracking tables (conntrack) and traffic fingerprinting.

### 1.2 Raw Socket Implementation
To inject packets with arbitrarily modified Layer 3 headers, Spoof Tunnel utilizes raw sockets (`AF_INET`, `SOCK_RAW`). It constructs the entire IPv4/IPv6 header manually, calculating the corresponding IP checksums in software.

* `gopacket` and `pcap` are heavily utilized to bypass the host kernel's network stack.
* **BPF Filters:** To prevent the host OS from dropping inbound spoofed packets or responding with `ICMP Destination Unreachable` / `TCP RST`, an aggressive Berkeley Packet Filter (BPF) limits the capture scope strictly to the tunnel's expected flow, bypassing local routing limits.

## 2. Supported Transports

### 2.1 ICMP (Echo Mode)
The tunnel encapsulates encrypted chunks inside standard `ICMP Echo Request (Type 8)` and `ICMP Echo Reply (Type 0)` packets. To network middleboxes, the traffic appears as benign ping sweeps or monitoring traffic.

### 2.2 UDP
Standard UDP datagrams are utilized with dynamically shiftable source ports. The protocol mimics connectionless DNS or custom UDP application patterns.

## 3. The Reliability Layer
Because ICMP and UDP provide no delivery guarantees, Spoof Tunnel implements a custom TCP-like reliability layer in user space. This is mandatory for maintaining stable TLS handshakes and in-order stream delivery.

* **Packet Sequencing and ACKs:** Every payload packet is wrapped in a `SeqDataPacket` format containing a monotonic sequence number (4 bytes). The recipient acknowledges data via `AckPacket`, utilizing a base sequence number accompanied by a 64-bit acknowledgment bitmap for handling blocks of data at once.
* **Flow Control & Buffers:** The `RecvBuffer` maintains an internal map of sequences. Out-of-order packets are buffered. Data is strictly delivered to the internal SOCKS5/Target TCP socket *in-order*.
* **Retransmission Engine:** An active background goroutine sweeps the `SendBuffer` every 100ms. Unacknowledged packets exceeding the `retransmit_timeout` are resent using exponential backoff up to a defined `max_retries` limit.

## 4. Session Multiplexing
Establishing a new tunnel session (INIT / INIT_ACK exchange) incurs significant latency. To mitigate this, Spoof Tunnel implements an internal multiplexer (Mux).

A single "Master Session" is established over the unreliable link. All incoming local TCP SOCKS5 connections are assigned a virtual 4-byte `StreamID` and multiplexed within this single master session.

* `0x01 MuxStreamOpen:` Followed by [StreamID:4][TargetLen:2][Target String]
* `0x02 MuxStreamData:` Followed by [StreamID:4][Raw Payload]
* `0x03 MuxStreamClose:` Followed by [StreamID:4]
* `0x04 MuxStreamAck:` Server acknowledgment for successful proxy stream creation.

## 5. Cryptography
Security and obfuscation are enforced via **ChaCha20-Poly1305 AEAD**. AEAD ensures that not a single byte of the IP payload or tunnel header structure is visible or modifiable by an active MITM attacker without immediately dropping the connection.

Each session initializes a randomized nonce mechanism to prevent replay attacks, while the static pre-shared Base64 keys act as the master cryptographic secret.

---

## Usage Instructions

### 1. Build the Binary
Spoof Tunnel is written in Go. You can build it using the standard Go toolchain:

```bash
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags="-s -w" -o spoof ./cmd/spoof/
```

### 2. Generate Cryptographic Keys
Before starting the tunnel, you need to generate a pair of Base64 private/public keys for both the server and the client.

```bash
./spoof keygen
```
*Take note of the Private Key and Public Key.* The Server's Public Key must be placed in the Client's `peer_public_key` field, and the Client's Public Key must be placed in the Server's `peer_public_key` field.

### 3. Running the Service
> **Note:** Raw sockets require elevated privileges. You must execute both the client and server binaries as `root` (or assign the `CAP_NET_RAW` capability).

**On the Server:**
```bash
sudo ./spoof -c server-config.json
```

**On the Client:**
```bash
sudo ./spoof -c client-config.json
```
Once the client connects, it will open a SOCKS5 proxy on `127.0.0.1:1080` (by default) that securely routes through the spoofed tunnel.

---

## Client Config

| Section      | Key                     | Type    | Description                                                                 |
|--------------|-------------------------|---------|-----------------------------------------------------------------------------|
| mode         | mode                    | string  | Must be "client"                                                            |
| transport    | type                    | string  | "udp" or "icmp" (tunnel transport)                                          |
| transport    | icmp_mode               | string  | "echo" or "reply" (only for ICMP)                                           |
| transport    | protocol_number         | int     | 0 (default, unused for ICMP/UDP)                                            |
| listen       | address                 | string  | SOCKS5 listening address (127.0.0.1)                                        |
| listen       | port                    | int     | SOCKS5 listening port (1080)                                                |
| server       | address                 | string  | Remote server actual IP to send tunnel packets to                           |
| server       | port                    | int     | Remote server port (for UDP)                                                |
| spoof        | source_ip               | string  | IP this client claims when sending outbound packets                         |
| spoof        | peer_spoof_ip           | string  | Expected spoofed source IP of incoming server packets (used by BPF filter)  |
| crypto       | private_key             | string  | Client's Base64 private key (from ./spoof keygen)                           |
| crypto       | peer_public_key         | string  | Server's Base64 public key                                                  |
| performance  | buffer_size             | int     | Main packet buffer size                                                     |
| performance  | mtu                     | int     | Max payload before encapsulation (e.g. 1400)                                |
| performance  | session_timeout         | int     | Master session timeout in seconds                                           |
| performance  | workers                 | int     | Number of packet processing goroutines                                      |
| performance  | read_buffer             | int     | Kernel socket read buffer size                                              |
| performance  | write_buffer            | int     | Kernel socket write buffer size                                             |
| fec          | enabled                 | bool    | true = enable Reed-Solomon Forward Error Correction                         |
| fec          | data_shards             | int     | Number of real data shards                                                  |
| fec          | parity_shards           | int     | Number of parity shards (recover up to this many lost packets)              |
| logging      | level                   | string  | "info", "debug", "warn", or "error"                                         |
| logging      | file                    | string  | Log file path (empty = stdout)                                              |

## Server Config

| Section      | Key                     | Type    | Description                                                                 |
|--------------|-------------------------|---------|-----------------------------------------------------------------------------|
| mode         | mode                    | string  | Must be "server"                                                            |
| transport    | type                    | string  | "udp" or "icmp" (tunnel transport)                                          |
| transport    | icmp_mode               | string  | "echo" or "reply" (only for ICMP)                                           |
| transport    | protocol_number         | int     | 0 (default, unused for ICMP/UDP)                                            |
| listen       | address                 | string  | Tunnel listening IP (0.0.0.0 for all interfaces)                            |
| listen       | port                    | int     | UDP listening port (ignored for ICMP)                                       |
| spoof        | source_ip               | string  | IP this server claims when sending outbound packets                         |
| spoof        | source_ipv6             | string  | IPv6 version of source_ip (leave empty if unused)                           |
| spoof        | peer_spoof_ip           | string  | Expected spoofed source IP of incoming client packets (used by BPF filter)  |
| spoof        | peer_spoof_ipv6         | string  | IPv6 version of peer_spoof_ip                                               |
| spoof        | client_real_ip          | string  | Client's actual real IP (server routes replies here)                        |
| spoof        | client_real_ipv6        | string  | IPv6 version of client_real_ip                                              |
| crypto       | private_key             | string  | Server's Base64 private key (from ./spoof keygen)                           |
| crypto       | peer_public_key         | string  | Client's Base64 public key                                                  |
| performance  | buffer_size             | int     | Main packet buffer size                                                     |
| performance  | mtu                     | int     | Max payload before encapsulation (e.g. 1400)                                |
| performance  | session_timeout         | int     | Master session timeout in seconds                                           |
| performance  | workers                 | int     | Number of packet processing goroutines                                      |
| performance  | read_buffer             | int     | Kernel socket read buffer size                                              |
| performance  | write_buffer            | int     | Kernel socket write buffer size                                             |
| reliability  | enabled                 | bool    | true = enable custom TCP-like reliability layer                             |
| reliability  | window_size             | int     | Max unacknowledged packets in flight                                        |
| reliability  | retransmit_timeout_ms   | int     | Base retransmission timeout (ms)                                            |
| reliability  | max_retries             | int     | Max retransmission attempts per packet                                      |
| reliability  | ack_interval_ms         | int     | How often to send ACKs (ms)                                                 |
| fec          | enabled                 | bool    | true = enable Reed-Solomon Forward Error Correction                         |
| fec          | data_shards             | int     | Number of real data shards                                                  |
| fec          | parity_shards           | int     | Number of parity shards (recover up to this many lost packets)              |
| keepalive    | enabled                 | bool    | true = send periodic keepalive pings                                        |
| keepalive    | interval_seconds        | int     | Seconds between keepalive packets                                           |
| keepalive    | timeout_seconds         | int     | Session drop timeout if no activity                                         |
| logging      | level                   | string  | "info", "debug", "warn", or "error"                                         |
| logging      | file                    | string  | Log file path (empty = stdout)                                              |