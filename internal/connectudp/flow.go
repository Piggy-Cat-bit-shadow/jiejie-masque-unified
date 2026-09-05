package connectudp

import (
	"sync"
	"sync/atomic"
	"time"
)

// FlowTracker owns active relay lifetimes. A flow is released exactly once,
// regardless of whether it finishes normally, is shut down, or expires idle.
type FlowTracker struct {
	mu    sync.Mutex
	flows map[*Flow]struct{}
}

type Flow struct {
	tracker         *FlowTracker
	resourceMu      sync.Mutex
	closeResource   func()
	closed          bool
	release         func()
	lastActivity    atomic.Int64
	activityPending atomic.Bool
	closeOnce       sync.Once
}

func NewFlowTracker() *FlowTracker { return &FlowTracker{flows: make(map[*Flow]struct{})} }

func (t *FlowTracker) New(release func()) *Flow {
	f := &Flow{tracker: t, release: release}
	f.lastActivity.Store(time.Now().UnixNano())
	t.mu.Lock()
	t.flows[f] = struct{}{}
	t.mu.Unlock()
	return f
}

func (f *Flow) SetCloseResource(closeResource func()) {
	f.resourceMu.Lock()
	closed := f.closed
	if !closed {
		f.closeResource = closeResource
	}
	f.resourceMu.Unlock()
	if closed && closeResource != nil {
		closeResource()
	}
}

// Touch records successful payload forwarding only. The reaper materializes
// the timestamp, so the forwarding hot path only performs an atomic mark.
func (f *Flow) Touch() { f.activityPending.Store(true) }

func (f *Flow) idleFor(now time.Time, timeout time.Duration) bool {
	if timeout <= 0 {
		return false
	}
	if f.activityPending.Swap(false) {
		f.lastActivity.Store(now.UnixNano())
		return false
	}
	return now.Sub(time.Unix(0, f.lastActivity.Load())) >= timeout
}

func (f *Flow) Close() {
	f.closeOnce.Do(func() {
		f.resourceMu.Lock()
		f.closed = true
		closeResource := f.closeResource
		f.resourceMu.Unlock()
		if closeResource != nil {
			closeResource()
		}
		f.tracker.mu.Lock()
		delete(f.tracker.flows, f)
		f.tracker.mu.Unlock()
		if f.release != nil {
			f.release()
		}
	})
}

func (t *FlowTracker) Count() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return len(t.flows)
}

func (t *FlowTracker) Reap(now time.Time, timeout time.Duration) int {
	t.mu.Lock()
	flows := make([]*Flow, 0, len(t.flows))
	for f := range t.flows {
		if f.idleFor(now, timeout) {
			flows = append(flows, f)
		}
	}
	t.mu.Unlock()
	reaped := 0
	for _, f := range flows {
		if f.activityPending.Load() {
			continue
		}
		f.Close()
		reaped++
	}
	return reaped
}

func (t *FlowTracker) Close() {
	t.mu.Lock()
	flows := make([]*Flow, 0, len(t.flows))
	for f := range t.flows {
		flows = append(flows, f)
	}
	t.mu.Unlock()
	for _, f := range flows {
		f.Close()
	}
}

func (t *FlowTracker) Run(ctxDone <-chan struct{}, idle, interval time.Duration) {
	if idle <= 0 {
		return
	}
	if interval <= 0 {
		interval = time.Minute
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctxDone:
			return
		case now := <-ticker.C:
			t.Reap(now, idle)
		}
	}
}
