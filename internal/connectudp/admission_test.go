package connectudp

import (
	"fmt"
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

func TestAdmissionSixteenUsersConcurrentChurn(t *testing.T) {
	a := NewAdmission(32, 2)
	start := make(chan struct{})
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		identity := fmt.Sprintf("user-%d", i)
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			for cycle := 0; cycle < 100; cycle++ {
				release, err := a.Acquire(identity)
				if err == nil {
					release()
				}
			}
		}()
	}
	close(start)
	wg.Wait()
	if total, users := a.Counts(); total != 0 || len(users) != 0 {
		t.Fatalf("leaked admission total=%d users=%v", total, users)
	}

	releases := make([]func(), 0, 2)
	for i := 0; i < 2; i++ {
		release, err := a.Acquire("user-0")
		if err != nil {
			t.Fatal(err)
		}
		releases = append(releases, release)
	}
	if _, err := a.Acquire("user-0"); err == nil {
		t.Fatal("per-user cap bypassed")
	}
	if release, err := a.Acquire("user-1"); err != nil {
		t.Fatal("other user blocked")
	} else {
		release()
	}
	for _, release := range releases {
		release()
	}
}
