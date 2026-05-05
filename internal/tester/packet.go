package tester

import (
	"encoding/binary"
	"math/rand"
	"net"
)

// BuildTCPSyn crafts a raw IP packet containing a TCP SYN segment.
func BuildTCPSyn(srcIP, dstIP net.IP, dstPort int) []byte {
	src := srcIP.To4()
	dst := dstIP.To4()

	pkt := make([]byte, 40)

	pkt[0] = 0x45
	pkt[1] = 0
	binary.BigEndian.PutUint16(pkt[2:], 40)
	binary.BigEndian.PutUint16(pkt[4:], uint16(rand.Intn(65535)))
	pkt[6] = 0x40
	pkt[7] = 0
	pkt[8] = 64
	pkt[9] = 6 // TCP
	copy(pkt[12:16], src)
	copy(pkt[16:20], dst)
	binary.BigEndian.PutUint16(pkt[10:], internetChecksum(pkt[:20]))

	tcp := pkt[20:]
	srcPort := uint16(1024 + rand.Intn(64511))
	binary.BigEndian.PutUint16(tcp[0:], srcPort)
	binary.BigEndian.PutUint16(tcp[2:], uint16(dstPort))
	binary.BigEndian.PutUint32(tcp[4:], rand.Uint32())
	binary.BigEndian.PutUint32(tcp[8:], 0)
	tcp[12] = 0x50
	tcp[13] = 0x02 // SYN
	binary.BigEndian.PutUint16(tcp[14:], 65535)
	binary.BigEndian.PutUint16(tcp[18:], 0)
	binary.BigEndian.PutUint16(tcp[16:], tcpChecksum(src, dst, tcp))

	return pkt
}

// BuildICMPEcho crafts a raw IP packet containing an ICMP Echo Request.
func BuildICMPEcho(srcIP, dstIP net.IP, id uint16, seq uint16) []byte {
	src := srcIP.To4()
	dst := dstIP.To4()

	pkt := make([]byte, 28)

	pkt[0] = 0x45
	pkt[1] = 0
	binary.BigEndian.PutUint16(pkt[2:], 28)
	binary.BigEndian.PutUint16(pkt[4:], uint16(rand.Intn(65535)))
	pkt[6] = 0x40
	pkt[7] = 0
	pkt[8] = 64
	pkt[9] = 1 // ICMP
	copy(pkt[12:16], src)
	copy(pkt[16:20], dst)
	binary.BigEndian.PutUint16(pkt[10:], internetChecksum(pkt[:20]))

	icmp := pkt[20:]
	icmp[0] = 8 // Echo Request
	icmp[1] = 0
	binary.BigEndian.PutUint16(icmp[4:], id)
	binary.BigEndian.PutUint16(icmp[6:], seq)
	binary.BigEndian.PutUint16(icmp[2:], internetChecksum(icmp))

	return pkt
}

func internetChecksum(data []byte) uint16 {
	var sum uint32
	for i := 0; i+1 < len(data); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(data[i:]))
	}
	if len(data)%2 == 1 {
		sum += uint32(data[len(data)-1]) << 8
	}
	for sum>>16 != 0 {
		sum = (sum >> 16) + (sum & 0xffff)
	}
	return ^uint16(sum)
}

func tcpChecksum(srcIP, dstIP []byte, tcpSegment []byte) uint16 {
	pseudo := make([]byte, 12+len(tcpSegment))
	copy(pseudo[0:4], srcIP)
	copy(pseudo[4:8], dstIP)
	pseudo[8] = 0
	pseudo[9] = 6
	binary.BigEndian.PutUint16(pseudo[10:], uint16(len(tcpSegment)))
	copy(pseudo[12:], tcpSegment)
	return internetChecksum(pseudo)
}
