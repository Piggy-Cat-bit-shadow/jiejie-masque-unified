package connectudp

import (
	"sync"
	"testing"
)

func TestAdmissionLimitsReleaseAndConcurrency(t *testing.T) {
	a := NewAdmission(16, 4)
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			u := string(rune('a' + i%4))
			rel, e := a.Acquire(u)
			if e != nil {
				t.Error(e)
				return
			}
			rel()
			rel()
		}(i)
	}
	wg.Wait()
	n, m := a.Counts()
	if n != 0 || len(m) != 0 {
		t.Fatalf("leaked admission: %d %#v", n, m)
	}
	rels := make([]func(), 0, 4)
	for i := 0; i < 4; i++ {
		r, e := a.Acquire("same")
		if e != nil {
			t.Fatal(e)
		}
		rels = append(rels, r)
	}
	if _, e := a.Acquire("same"); e == nil {
		t.Fatal("per-user cap not enforced")
	}
	for _, r := range rels {
		r()
	}
}
