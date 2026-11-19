package main

import (
	"context"
	"sync"
)

// limiter is a bounded-capacity semaphore with lease-based slots.
//
// A lease can only be returned to the pool once. A duplicated or spurious
// Release is ignored instead of over-releasing the semaphore, which would
// otherwise make the slot count drift until later targets can never be
// scheduled. That is the "abnormal release self-heals" guarantee: a buggy
// double-release cannot permanently starve the rest of the batch.
type limiter struct {
	mu       sync.Mutex
	capacity int
	inUse    int
	waiters  []*waiter
}

type waiter struct {
	ch chan struct{}
	// granted is set while holding l.mu when the slot is handed over. It
	// lets Acquire tell a genuine hand-off from a waiter that was already
	// cancelled.
	granted bool
}

func newLimiter(capacity int) *limiter {
	if capacity < 1 {
		capacity = 1
	}
	return &limiter{capacity: capacity}
}

// Acquire takes a slot, blocking until one is free or ctx is done. Slot
// ownership is transferred directly to the waiter, so two waiters can never
// observe the same slot as free.
func (l *limiter) Acquire(ctx context.Context) (*lease, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	l.mu.Lock()
	if l.inUse < l.capacity {
		l.inUse++
		l.mu.Unlock()
		return &lease{l: l}, nil
	}
	w := &waiter{ch: make(chan struct{}, 1)}
	l.waiters = append(l.waiters, w)
	l.mu.Unlock()

	select {
	case <-w.ch:
		return &lease{l: l}, nil
	case <-ctx.Done():
		l.mu.Lock()
		defer l.mu.Unlock()
		if w.granted {
			// The slot was handed to us as cancellation raced in. We own it,
			// so hand it back rather than leaking it.
			l.releaseLocked()
			return nil, ctx.Err()
		}
		l.removeWaiterLocked(w)
		return nil, ctx.Err()
	}
}

func (l *limiter) removeWaiterLocked(w *waiter) {
	for i, other := range l.waiters {
		if other == w {
			l.waiters = append(l.waiters[:i], l.waiters[i+1:]...)
			return
		}
	}
}

// Release returns a slot and hands it to the oldest waiter, if any.
func (l *limiter) Release() {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.releaseLocked()
}

func (l *limiter) releaseLocked() {
	if l.inUse > 0 {
		l.inUse--
	}
	if len(l.waiters) == 0 {
		return
	}
	if l.inUse >= l.capacity {
		return
	}
	w := l.waiters[0]
	l.waiters = l.waiters[1:]
	w.granted = true
	l.inUse++
	select {
	case w.ch <- struct{}{}:
	default:
	}
}

// InUse reports the number of slots currently held. Used by tests and by the
// batch runner to confirm no slot was leaked.
func (l *limiter) InUse() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.inUse
}

func (l *limiter) Capacity() int { return l.capacity }

// lease is a single owner's claim on a slot. Release is idempotent and safe
// to call from a deferred function during a panic.
type lease struct {
	l    *limiter
	once sync.Once
}

func (le *lease) Release() {
	if le == nil || le.l == nil {
		return
	}
	le.once.Do(le.l.Release)
}
