package pool

import (
	"context"
	"testing"
	"time"
)

func TestRejectPolicy(t *testing.T) {
	p := New(2, PolicyReject, 0)
	ctx := context.Background()
	r1, ok1 := p.Acquire(ctx)
	r2, ok2 := p.Acquire(ctx)
	_, ok3 := p.Acquire(ctx)
	if !ok1 || !ok2 || ok3 {
		t.Fatalf("expected 2 acquires then reject, got %v %v %v", ok1, ok2, ok3)
	}
	if p.Active() != 2 {
		t.Fatalf("active=%d", p.Active())
	}
	r1()
	if p.Active() != 1 {
		t.Fatalf("active after release=%d", p.Active())
	}
	if _, ok := p.Acquire(ctx); !ok {
		t.Fatal("slot should be reusable after release")
	}
	r2()
	r2() // double release must be safe
}

func TestQueuePolicy(t *testing.T) {
	p := New(1, PolicyQueue, 100*time.Millisecond)
	ctx := context.Background()
	r1, _ := p.Acquire(ctx)
	start := time.Now()
	_, ok := p.Acquire(ctx)
	if ok || time.Since(start) < 80*time.Millisecond {
		t.Fatalf("expected timeout reject, ok=%v waited=%v", ok, time.Since(start))
	}
	go func() {
		time.Sleep(30 * time.Millisecond)
		r1()
	}()
	r2, ok := p.Acquire(ctx)
	if !ok {
		t.Fatal("expected queued acquire to succeed after release")
	}
	r2()
}

func TestQueueContextCancel(t *testing.T) {
	p := New(1, PolicyQueue, time.Minute)
	ctx := context.Background()
	r1, _ := p.Acquire(ctx)
	defer r1()
	cctx, cancel := context.WithCancel(ctx)
	go func() {
		time.Sleep(30 * time.Millisecond)
		cancel()
	}()
	if _, ok := p.Acquire(cctx); ok {
		t.Fatal("expected cancellation")
	}
}

func TestUnlimited(t *testing.T) {
	p := New(0, PolicyReject, 0)
	var rels []ReleaseFunc
	for i := 0; i < 1000; i++ {
		r, ok := p.Acquire(context.Background())
		if !ok {
			t.Fatal("unlimited pool must not reject")
		}
		rels = append(rels, r)
	}
	if p.Active() != 1000 {
		t.Fatalf("active=%d", p.Active())
	}
	for _, r := range rels {
		r()
	}
	if p.Active() != 0 {
		t.Fatalf("active after release=%d", p.Active())
	}
}
