package session

import "testing"

func TestPacketPoolAcquireForReadPreservesHeadroom(t *testing.T) {
	pool := NewPacketPool(1280)
	pkt := pool.AcquireForRead()
	if len(pkt.Buffer) != 1290 {
		t.Fatalf("backing length = %d, want 1290", len(pkt.Buffer))
	}
	if len(pkt.Data) != 1281 {
		t.Fatalf("read length = %d, want 1281", len(pkt.Data))
	}
	pkt.Buffer[0] = 0xa5
	pkt.Data[0] = 0x45
	if !pool.CommitRead(pkt, 1280) {
		t.Fatal("MTU-sized read rejected")
	}
	if len(pkt.Data) != 1280 || pkt.Buffer[0] != 0xa5 || pkt.Data[0] != 0x45 {
		t.Fatalf("committed packet lost layout: len=%d headroom=%#x payload=%#x", len(pkt.Data), pkt.Buffer[0], pkt.Data[0])
	}
	pool.Put(pkt)
}

func TestPacketPoolRejectsReadSentinel(t *testing.T) {
	pool := NewPacketPool(1280)
	pkt := pool.AcquireForRead()
	if pool.CommitRead(pkt, 1281) {
		t.Fatal("oversized sentinel read accepted")
	}
	pool.Put(pkt)
}

func TestPacketBufferReleaseIsIdempotent(t *testing.T) {
	pool := NewPacketPool(1280)
	pkt := pool.Get(64)
	if pkt.released.Load() {
		t.Fatal("new packet starts released")
	}

	pkt.Release()
	if !pkt.released.Load() {
		t.Fatal("first release did not mark packet released")
	}
	pkt.Release()
	if !pkt.released.Load() {
		t.Fatal("duplicate release changed released state")
	}
}

func TestPacketPoolGetStartsNewReleaseGeneration(t *testing.T) {
	pool := NewPacketPool(1280)
	pkt := pool.Get(64)
	pkt.Release()

	next := pool.Get(64)
	if next.released.Load() {
		t.Fatal("new ownership generation starts released")
	}
	if len(next.Data) != 64 {
		t.Fatalf("packet data length = %d, want 64", len(next.Data))
	}
	next.Release()
}
