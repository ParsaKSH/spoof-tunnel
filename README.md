# Spoof Tunnel
[Persian-فارسی](README-fa.md)

Spoof Tunnel is a Layer 3/Layer 4 tunneling proxy designed to bypass Deep Packet Inspection (DPI) and strict stateful firewalls through **mutual bidirectional IP spoofing**. 

Unlike traditional tunneling protocols that establish a stateful connection between a fixed client IP and a fixed server IP, Spoof Tunnel completely decouples the logical session from the physical network addresses by forging the `Source IP` field in the IP header at both endpoints.

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
./spoof generate-keys
```
*Take note of the Private Key and Public Key.* The Server's Public Key must be placed in the Client's `peer_public_key` field, and the Client's Public Key must be placed in the Server's `peer_public_key` field.

### 3. Running the Service
> **Note:** Raw sockets require elevated privileges. You must execute both the client and server binaries as `root` (or assign the `CAP_NET_RAW` capability).

**On the Server:**
```bash
sudo ./spoof server -c server-config.json
```

**On the Client:**
```bash
sudo ./spoof client -c client-config.json
```
Once the client connects, it will open a SOCKS5 proxy on `127.0.0.1:1080` (by default) that securely routes through the spoofed tunnel.

---

## Configuration File Parameters (`config.json`)

Here is a detailed breakdown of the `config.json` parameters required to operate the tunnel:

| Key Category/Path | Type | Description |
| :--- | :--- | :--- |
| `mode` | String | `"client"` or `"server"`. Dictates the operational mode of the binary. |
| **`transport`** | | |
| `transport.type` | String | `"udp"` or `"icmp"`. The underlying protocol used for the tunnel. |
| `transport.icmp_mode` | String | `"echo"` or `"reply"`. Used when type is ICMP. |
| **`listen`** | | |
| `listen.address` | String | **Client**: SOCKS5 bind address (e.g., `127.0.0.1`).<br>**Server**: The IP address where the server expects the tunnel traffic to arrive. |
| `listen.port` | Integer| **Client**: SOCKS5 bind port (e.g., `1080`).<br>**Server**: The tunnel listening port (only applicable for UDP mode). |
| **`server`** | | |
| `server.address` | String | **Client only**: The actual remote server IP address to send packets to. |
| `server.port` | Integer| **Client only**: The remote server port to send packets to. |
| **`spoof`** | | |
| `spoof.source_ip` | String | The IP address this node will claim to be when sending outbound packets. |
| `spoof.peer_spoof_ip` | String | The specific expected fake source IP of the incoming packets from the peer. Used by the BPF filter to capture the tunnel traffic. |
| **`crypto`** | | |
| `crypto.private_key`| String | The node's private key (Base64) generated via `generate-keys`. |
| `crypto.peer_public_key`| String| The peer's public key (Base64). Client puts Server's public key here, and vice versa. |
| **`performance`** | | |
| `performance.mtu` | Integer| Maximum payload sizing before tunnel encapsulation. Crucial to adjust down (e.g., `1300` or `1400`) to avoid Layer 3 IP fragmentation. |
| `performance.session_timeout` | Integer| General session timeout duration in seconds. |
| `performance.workers` | Integer| Number of concurrent packet processing workers. |
| **`reliability`** | | |
| `reliability.enabled` | Boolean| Set to `true` to enable the custom TCP-like delivery layer. |
| `reliability.window_size` | Integer| Maximum number of unacknowledged packets allowed in-flight simultaneously. |
| `reliability.retransmit_timeout_ms`| Integer| Base milliseconds to wait before triggering a packet retransmission. |
| `reliability.max_retries` | Integer| Maximum number of times to re-send a dropped packet before giving up. |
| `reliability.ack_interval_ms` | Integer| How frequently (in ms) to piggyback or send pending ACKs. |
| **`keepalive`** | | |
| `keepalive.enabled` | Boolean| Enables periodic pinging to keep the NAT/State table (if any) and tunnel session alive. |
| `keepalive.interval_seconds` | Integer| Interval between ping packets. |
| `keepalive.timeout_seconds` | Integer| Time without activity before dropping the master session. |


