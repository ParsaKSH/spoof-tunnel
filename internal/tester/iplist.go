package tester

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"os"
	"sort"
	"strings"
)

// ParseIPList reads an IP list file and returns all individual IPs.
// Supported formats per line:
//   - Single IP:   192.168.1.1
//   - CIDR:        192.168.70.5/31
//   - Range:       192.168.60.5-192.168.60.10
func ParseIPList(path string) ([]net.IP, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open IP list: %w", err)
	}
	defer f.Close()

	return ParseIPListFromReader(f)
}

// ParseIPListFromString parses IPs from a newline-separated string.
func ParseIPListFromString(data string) ([]net.IP, error) {
	return ParseIPListFromReader(strings.NewReader(data))
}

// ParseIPListFromReader parses IPs from any reader.
func ParseIPListFromReader(r interface{ Read([]byte) (int, error) }) ([]net.IP, error) {
	var ips []net.IP
	scanner := bufio.NewScanner(r)
	lineNum := 0

	for scanner.Scan() {
		lineNum++
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		parsed, err := parseLine(line)
		if err != nil {
			return nil, fmt.Errorf("line %d: %w", lineNum, err)
		}
		ips = append(ips, parsed...)
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read IP list: %w", err)
	}

	return ips, nil
}

// IPRange represents a contiguous range of IPv4 addresses [Start, End] inclusive.
type IPRange struct {
	Start uint32
	End   uint32
}

// IPRangeSet is a sorted, merged set of IP ranges for O(log n) membership testing.
type IPRangeSet struct {
	ranges []IPRange
	total  int64
}

// ParseIPRangesFromString parses IP list text into a compact range set.
// This avoids allocating individual net.IP for every address — only storing
// the ranges themselves. For 10k /24 CIDRs this uses ~80 KB instead of ~160 MB.
func ParseIPRangesFromString(data string) (*IPRangeSet, error) {
	return ParseIPRangesFromReader(strings.NewReader(data))
}

// ParseIPRangesFromReader parses IP ranges from any reader.
func ParseIPRangesFromReader(r io.Reader) (*IPRangeSet, error) {
	var ranges []IPRange
	scanner := bufio.NewScanner(r)
	lineNum := 0

	for scanner.Scan() {
		lineNum++
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// v2 output format: "1.2.3.4 5/10 50.0%" — extract IP only
		if parts := strings.Fields(line); len(parts) >= 2 && strings.Contains(parts[1], "/") {
			line = parts[0]
		}

		rng, err := parseLineToRange(line)
		if err != nil {
			return nil, fmt.Errorf("line %d: %w", lineNum, err)
		}
		ranges = append(ranges, rng...)
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read IP list: %w", err)
	}

	// Sort and merge overlapping ranges
	sort.Slice(ranges, func(i, j int) bool { return ranges[i].Start < ranges[j].Start })
	merged := make([]IPRange, 0, len(ranges))
	for _, r := range ranges {
		if len(merged) > 0 && r.Start <= merged[len(merged)-1].End+1 {
			if r.End > merged[len(merged)-1].End {
				merged[len(merged)-1].End = r.End
			}
		} else {
			merged = append(merged, r)
		}
	}

	var total int64
	for _, r := range merged {
		total += int64(r.End-r.Start) + 1
	}

	return &IPRangeSet{ranges: merged, total: total}, nil
}

// Contains checks if an IP (as uint32) belongs to this range set.
// Uses binary search — O(log n) per lookup.
func (s *IPRangeSet) Contains(ip uint32) bool {
	idx := sort.Search(len(s.ranges), func(i int) bool {
		return s.ranges[i].End >= ip
	})
	return idx < len(s.ranges) && s.ranges[idx].Start <= ip
}

// Total returns the total number of individual IPs in the set.
func (s *IPRangeSet) Total() int64 {
	return s.total
}

// IterateIPs calls fn for each individual IP in the set.
// Used by sender to iterate without holding all IPs in memory.
func (s *IPRangeSet) IterateIPs(fn func(ip net.IP) bool) {
	ipBuf := make(net.IP, 4)
	for _, r := range s.ranges {
		for v := r.Start; v <= r.End; v++ {
			binary.BigEndian.PutUint32(ipBuf, v)
			if !fn(ipBuf) {
				return
			}
		}
	}
}

func parseLineToRange(line string) ([]IPRange, error) {
	if strings.Contains(line, "-") {
		return parseRangeToRange(line)
	}
	if strings.Contains(line, "/") {
		return parseCIDRToRange(line)
	}
	ip := net.ParseIP(line)
	if ip == nil {
		return nil, fmt.Errorf("invalid IP: %s", line)
	}
	ip4 := ip.To4()
	if ip4 == nil {
		return nil, fmt.Errorf("only IPv4 supported: %s", line)
	}
	v := binary.BigEndian.Uint32(ip4)
	return []IPRange{{Start: v, End: v}}, nil
}

func parseCIDRToRange(cidr string) ([]IPRange, error) {
	ip, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, fmt.Errorf("invalid CIDR: %w", err)
	}
	ip = ip.To4()
	if ip == nil {
		return nil, fmt.Errorf("only IPv4 CIDR supported: %s", cidr)
	}
	start := binary.BigEndian.Uint32(ip.Mask(ipNet.Mask))
	ones, bits := ipNet.Mask.Size()
	hostBits := uint(bits - ones)
	end := start | ((1 << hostBits) - 1)
	return []IPRange{{Start: start, End: end}}, nil
}

func parseRangeToRange(r string) ([]IPRange, error) {
	parts := strings.SplitN(r, "-", 2)
	if len(parts) != 2 {
		return nil, fmt.Errorf("invalid range format: %s", r)
	}
	startIP := net.ParseIP(strings.TrimSpace(parts[0])).To4()
	endIP := net.ParseIP(strings.TrimSpace(parts[1])).To4()
	if startIP == nil || endIP == nil {
		return nil, fmt.Errorf("invalid IPs in range: %s", r)
	}
	start := binary.BigEndian.Uint32(startIP)
	end := binary.BigEndian.Uint32(endIP)
	if start > end {
		return nil, fmt.Errorf("start IP > end IP in range: %s", r)
	}
	return []IPRange{{Start: start, End: end}}, nil
}

func parseLine(line string) ([]net.IP, error) {
	// v2 output format: "1.2.3.4 5/10 50.0%" — extract IP only
	if parts := strings.Fields(line); len(parts) >= 2 && strings.Contains(parts[1], "/") {
		line = parts[0]
	}

	if strings.Contains(line, "-") {
		return parseRange(line)
	}
	if strings.Contains(line, "/") {
		return parseCIDR(line)
	}

	ip := net.ParseIP(line)
	if ip == nil {
		return nil, fmt.Errorf("invalid IP: %s", line)
	}
	ip = ip.To4()
	if ip == nil {
		return nil, fmt.Errorf("only IPv4 supported: %s", line)
	}
	return []net.IP{ip}, nil
}

func parseCIDR(cidr string) ([]net.IP, error) {
	ip, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, fmt.Errorf("invalid CIDR: %w", err)
	}
	ip = ip.To4()
	if ip == nil {
		return nil, fmt.Errorf("only IPv4 CIDR supported: %s", cidr)
	}
	var ips []net.IP
	for current := ip.Mask(ipNet.Mask); ipNet.Contains(current); incIP(current) {
		dup := make(net.IP, 4)
		copy(dup, current)
		ips = append(ips, dup)
	}
	return ips, nil
}

func parseRange(r string) ([]net.IP, error) {
	parts := strings.SplitN(r, "-", 2)
	if len(parts) != 2 {
		return nil, fmt.Errorf("invalid range format: %s", r)
	}
	startIP := net.ParseIP(strings.TrimSpace(parts[0])).To4()
	endIP := net.ParseIP(strings.TrimSpace(parts[1])).To4()
	if startIP == nil || endIP == nil {
		return nil, fmt.Errorf("invalid IPs in range: %s", r)
	}
	start := binary.BigEndian.Uint32(startIP)
	end := binary.BigEndian.Uint32(endIP)
	if start > end {
		return nil, fmt.Errorf("start IP > end IP in range: %s", r)
	}
	ips := make([]net.IP, 0, end-start+1)
	for i := start; i <= end; i++ {
		ip := make(net.IP, 4)
		binary.BigEndian.PutUint32(ip, i)
		ips = append(ips, ip)
	}
	return ips, nil
}

func incIP(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}
