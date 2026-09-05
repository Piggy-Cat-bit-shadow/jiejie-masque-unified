package connectudp

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestFlowTrackerIdleReleasesExactlyOnce(t *testing.T) {
	tracker := NewFlowTracker()
	var closed, released atomic.Int32
	flow := tracker.New(func() { released.Add(1) })
	flow.SetCloseResource(func() { closed.Add(1) })
	flow.lastActivity.Store(time.Now().Add(-time.Second).UnixNano())
	if got := tracker.Reap(time.Now(), time.Millisecond); got != 1 {
		t.Fatalf("reaped=%d", got)
	}
	flow.Close()
	if tracker.Count() != 0 || closed.Load() != 1 || released.Load() != 1 {
		t.Fatalf("count=%d closed=%d released=%d", tracker.Count(), closed.Load(), released.Load())
	}
}

func TestFlowTrackerActivityRefreshesDeadline(t *testing.T) {
	tracker := NewFlowTracker()
	flow := tracker.New(func() {})
	flow.lastActivity.Store(time.Now().Add(-time.Second).UnixNano())
	flow.Touch()
	if got := tracker.Reap(time.Now(), 100*time.Millisecond); got != 0 || tracker.Count() != 1 {
		t.Fatalf("reaped=%d count=%d", got, tracker.Count())
	}
	flow.Close()
}

func TestFlowTouchCoalescesAndConcurrentReapDoesNotCloseActiveFlow(t *testing.T) {
	tracker := NewFlowTracker()
	var released atomic.Int32
	flow := tracker.New(func() { released.Add(1) })
	flow.lastActivity.Store(time.Now().Add(-time.Second).UnixNano())
	flow.Touch()
	const workers = 8
	var wg sync.WaitGroup
	for range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 1000 {
				flow.Touch()
			}
		}()
	}
	for range 100 {
		tracker.Reap(time.Now(), time.Second)
	}
	wg.Wait()
	if tracker.Reap(time.Now(), time.Second) != 0 || released.Load() != 0 {
		t.Fatalf("active flow was reaped: count=%d released=%d", tracker.Count(), released.Load())
	}
	flow.Close()
	if released.Load() != 1 {
		t.Fatalf("released=%d, want 1", released.Load())
	}
}
