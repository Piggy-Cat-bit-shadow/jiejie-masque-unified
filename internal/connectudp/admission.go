package connectudp

import (
	"fmt"
	"sync"
)

type Admission struct {
	mu                sync.Mutex
	total             int
	byUser            map[string]int
	maxTotal, maxUser int
}

func NewAdmission(total, user int) *Admission {
	return &Admission{byUser: make(map[string]int), maxTotal: total, maxUser: user}
}
func (a *Admission) Acquire(user string) (func(), error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.total >= a.maxTotal {
		return nil, fmt.Errorf("flow capacity exhausted")
	}
	if a.byUser[user] >= a.maxUser {
		return nil, fmt.Errorf("user flow capacity exhausted")
	}
	a.total++
	a.byUser[user]++
	var once sync.Once
	return func() {
		once.Do(func() {
			a.mu.Lock()
			a.total--
			a.byUser[user]--
			if a.byUser[user] == 0 {
				delete(a.byUser, user)
			}
			a.mu.Unlock()
		})
	}, nil
}
func (a *Admission) Counts() (int, map[string]int) {
	a.mu.Lock()
	defer a.mu.Unlock()
	m := make(map[string]int, len(a.byUser))
	for k, v := range a.byUser {
		m[k] = v
	}
	return a.total, m
}
