#ifndef SPOOF_TRANSPORT_H
#define SPOOF_TRANSPORT_H

#include <stdint.h>

typedef void* SpoofHandle;

// TCP Sender
SpoofHandle spoof_tcp_sender_new(uint8_t* src_ip, uint16_t src_port, int32_t mtu);
SpoofHandle spoof_tcp_sender_new_multi(uint8_t* ip_array, uintptr_t ip_count, uint16_t src_port, int32_t mtu);
int32_t spoof_tcp_sender_send(SpoofHandle h, uint8_t* payload, uintptr_t len, uint8_t* dst_ip, uint16_t dst_port);
void spoof_tcp_sender_close(SpoofHandle h);

// TCP Receiver
SpoofHandle spoof_tcp_receiver_new(uint16_t listen_port, uint8_t* peer_spoof_ip, int32_t buf_size);
int32_t spoof_tcp_receiver_recv(SpoofHandle h, uint8_t* out_buf, uintptr_t out_buf_len, uint8_t* src_ip_out, uint16_t* src_port_out);
void spoof_tcp_receiver_close(SpoofHandle h);

// UDP Sender
SpoofHandle spoof_udp_sender_new(uint8_t* src_ip, uint16_t src_port, int32_t mtu);
SpoofHandle spoof_udp_sender_new_multi(uint8_t* ip_array, uintptr_t ip_count, uint16_t src_port, int32_t mtu);
int32_t spoof_udp_sender_send(SpoofHandle h, uint8_t* payload, uintptr_t len, uint8_t* dst_ip, uint16_t dst_port);
void spoof_udp_sender_close(SpoofHandle h);

// ICMP Sender (proto 1, type 8)
SpoofHandle spoof_icmp_sender_new_multi(uint8_t* ip_array, uintptr_t ip_count, uint16_t icmp_id, int32_t mtu);
int32_t spoof_icmp_sender_send(SpoofHandle h, uint8_t* payload, uintptr_t len, uint8_t* dst_ip);
void spoof_icmp_sender_close(SpoofHandle h);

// ICMP Receiver (proto 1, type 8)
SpoofHandle spoof_icmp_receiver_new(uint8_t* peer_ip, int32_t buf_size);
int32_t spoof_icmp_receiver_recv(SpoofHandle h, uint8_t* out_buf, uintptr_t out_buf_len, uint8_t* src_ip_out);
void spoof_icmp_receiver_close(SpoofHandle h);

// ICMPv6 Sender (proto 58, type 128)
SpoofHandle spoof_icmpv6_sender_new_multi(uint8_t* ip_array, uintptr_t ip_count, uint16_t icmp_id, int32_t mtu);
int32_t spoof_icmpv6_sender_send(SpoofHandle h, uint8_t* payload, uintptr_t len, uint8_t* dst_ip);
void spoof_icmpv6_sender_close(SpoofHandle h);

// ICMPv6 Receiver (proto 58, type 128)
SpoofHandle spoof_icmpv6_receiver_new(uint8_t* peer_ip, int32_t buf_size);
int32_t spoof_icmpv6_receiver_recv(SpoofHandle h, uint8_t* out_buf, uintptr_t out_buf_len, uint8_t* src_ip_out);
void spoof_icmpv6_receiver_close(SpoofHandle h);

#endif
