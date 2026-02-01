package fec

import (
	"bytes"
	"testing"
)

func TestEncoderDecoder(t *testing.T) {
	dataShards := 5
	parityShards := 2

	enc, err := NewEncoder(dataShards, parityShards)
	if err != nil {
		t.Fatalf("NewEncoder failed: %v", err)
	}

	_, err = NewDecoder(dataShards, parityShards)
	if err != nil {
		t.Fatalf("NewDecoder failed: %v", err)
	}

	// Create test packets
	packets := make([][]byte, dataShards)
	for i := 0; i < dataShards; i++ {
		packets[i] = []byte{byte(i), byte(i + 1), byte(i + 2), byte(i + 3)}
	}

	// Encode packets
	var shards [][]byte
	for i, pkt := range packets {
		result, err := enc.AddPacket(pkt)
		if err != nil {
			t.Fatalf("AddPacket %d failed: %v", i, err)
		}
		if result != nil {
			shards = result
		}
	}

	if shards == nil {
		t.Fatal("Expected shards after adding all packets")
	}

	if len(shards) != dataShards+parityShards {
		t.Fatalf("Expected %d shards, got %d", dataShards+parityShards, len(shards))
	}

	// Test 1: All shards received - should recover original data
	t.Run("AllShardsReceived", func(t *testing.T) {
		dec2, _ := NewDecoder(dataShards, parityShards)
		var received [][]byte

		for _, shard := range shards {
			orig, recovered, err := dec2.AddShard(shard)
			if err != nil {
				t.Fatalf("AddShard failed: %v", err)
			}
			if orig != nil {
				received = append(received, orig)
			}
			received = append(received, recovered...)
		}

		if len(received) != dataShards {
			t.Fatalf("Expected %d packets, got %d", dataShards, len(received))
		}

		for i, pkt := range received {
			if !bytes.Equal(pkt, packets[i]) {
				t.Errorf("Packet %d mismatch: got %v, want %v", i, pkt, packets[i])
			}
		}
	})

	// Test 2: One shard lost - should recover
	t.Run("OneShardLost", func(t *testing.T) {
		dec2, _ := NewDecoder(dataShards, parityShards)
		var received [][]byte
		lostIdx := 2 // Lose the 3rd data shard

		for i, shard := range shards {
			if i == lostIdx {
				continue // Skip this shard
			}
			orig, recovered, err := dec2.AddShard(shard)
			if err != nil {
				t.Fatalf("AddShard failed: %v", err)
			}
			if orig != nil {
				received = append(received, orig)
			}
			received = append(received, recovered...)
		}

		if len(received) != dataShards {
			t.Fatalf("Expected %d packets after recovery, got %d", dataShards, len(received))
		}
	})

	// Test 3: Two shards lost (max recoverable) - should recover
	t.Run("TwoShardsLost", func(t *testing.T) {
		dec2, _ := NewDecoder(dataShards, parityShards)
		var received [][]byte
		lostIdxs := map[int]bool{1: true, 3: true} // Lose 2 data shards

		for i, shard := range shards {
			if lostIdxs[i] {
				continue
			}
			orig, recovered, err := dec2.AddShard(shard)
			if err != nil {
				t.Fatalf("AddShard failed: %v", err)
			}
			if orig != nil {
				received = append(received, orig)
			}
			received = append(received, recovered...)
		}

		if len(received) != dataShards {
			t.Fatalf("Expected %d packets after recovery, got %d", dataShards, len(received))
		}
	})
}

func TestFlush(t *testing.T) {
	enc, _ := NewEncoder(5, 2)
	dec, _ := NewDecoder(5, 2)

	// Add only 3 packets (less than dataShards)
	packets := [][]byte{
		{1, 2, 3},
		{4, 5, 6},
		{7, 8, 9},
	}

	for _, pkt := range packets {
		_, err := enc.AddPacket(pkt)
		if err != nil {
			t.Fatalf("AddPacket failed: %v", err)
		}
	}

	// Flush remaining
	shards, err := enc.Flush()
	if err != nil {
		t.Fatalf("Flush failed: %v", err)
	}

	if shards == nil {
		t.Fatal("Expected shards from flush")
	}

	// Decode all shards
	var received [][]byte
	for _, shard := range shards {
		orig, recovered, err := dec.AddShard(shard)
		if err != nil {
			t.Fatalf("AddShard failed: %v", err)
		}
		if orig != nil {
			received = append(received, orig)
		}
		received = append(received, recovered...)
	}

	// Should get back the 3 original packets (padded shards have 0 length)
	if len(received) != 3 {
		t.Fatalf("Expected 3 packets, got %d", len(received))
	}

	for i, pkt := range received {
		if !bytes.Equal(pkt, packets[i]) {
			t.Errorf("Packet %d mismatch: got %v, want %v", i, pkt, packets[i])
		}
	}
}

func TestVariableSizePackets(t *testing.T) {
	enc, _ := NewEncoder(3, 1)
	dec, _ := NewDecoder(3, 1)

	// Variable size packets
	packets := [][]byte{
		{1, 2},
		{3, 4, 5, 6, 7},
		{8},
	}

	var shards [][]byte
	for _, pkt := range packets {
		result, _ := enc.AddPacket(pkt)
		if result != nil {
			shards = result
		}
	}

	// Lose one shard (the second data shard)
	var received [][]byte
	for i, shard := range shards {
		if i == 1 {
			continue
		}
		orig, recovered, _ := dec.AddShard(shard)
		if orig != nil {
			received = append(received, orig)
		}
		received = append(received, recovered...)
	}

	if len(received) != 3 {
		t.Fatalf("Expected 3 packets, got %d", len(received))
	}

	// Check that all packets are present (order may vary due to recovery)
	found := make([]bool, len(packets))
	for _, recv := range received {
		for i, pkt := range packets {
			if bytes.Equal(recv, pkt) {
				found[i] = true
				break
			}
		}
	}

	for i, f := range found {
		if !f {
			t.Errorf("Packet %d not found in received: %v", i, packets[i])
		}
	}
}
