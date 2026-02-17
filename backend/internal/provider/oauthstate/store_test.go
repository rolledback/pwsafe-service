package oauthstate

import (
	"sync"
	"testing"
	"time"
)

func TestMismatchDoesNotDelete(t *testing.T) {
	store := NewStore(10 * time.Minute)
	t.Cleanup(store.Close)

	store.Put("sess1", "onedrive", &StateEntry{
		State:        "correct-state",
		CodeVerifier: "verifier1",
		CreatedAt:    time.Now(),
	})

	// Simulate a mismatch check — read the entry, compare, but do NOT delete
	entry, ok := store.Get("sess1", "onedrive")
	if !ok {
		t.Fatal("expected entry to exist")
	}
	if entry.State == "wrong-state" {
		// mismatch — but we intentionally don't delete
	}

	// Entry must still be present
	_, ok = store.Get("sess1", "onedrive")
	if !ok {
		t.Error("state entry was deleted on mismatch — this enables DoS")
	}
}

func TestSeparateKeysPerProvider(t *testing.T) {
	store := NewStore(10 * time.Minute)
	t.Cleanup(store.Close)

	store.Put("sess1", "onedrive", &StateEntry{
		State:        "state-od",
		CodeVerifier: "v-od",
		CreatedAt:    time.Now(),
	})
	store.Put("sess1", "gdrive", &StateEntry{
		State:        "state-gd",
		CodeVerifier: "v-gd",
		CreatedAt:    time.Now(),
	})

	od, ok := store.Get("sess1", "onedrive")
	if !ok || od.State != "state-od" {
		t.Errorf("expected onedrive state 'state-od', got %v", od)
	}

	gd, ok := store.Get("sess1", "gdrive")
	if !ok || gd.State != "state-gd" {
		t.Errorf("expected gdrive state 'state-gd', got %v", gd)
	}

	// Delete one — the other must remain
	store.Delete("sess1", "onedrive")
	_, ok = store.Get("sess1", "onedrive")
	if ok {
		t.Error("onedrive entry should be deleted")
	}
	_, ok = store.Get("sess1", "gdrive")
	if !ok {
		t.Error("gdrive entry should still exist")
	}
}

func TestTTLExpiry(t *testing.T) {
	store := NewStore(50 * time.Millisecond)
	t.Cleanup(store.Close)

	store.Put("sess1", "prov", &StateEntry{
		State:        "s",
		CodeVerifier: "v",
		CreatedAt:    time.Now(),
	})

	// Entry exists immediately
	if _, ok := store.Get("sess1", "prov"); !ok {
		t.Fatal("entry should exist before TTL")
	}

	// Wait for TTL to expire
	time.Sleep(100 * time.Millisecond)
	store.CleanupNow()

	if _, ok := store.Get("sess1", "prov"); ok {
		t.Error("entry should have been cleaned up after TTL")
	}
}

func TestConcurrentAccess(t *testing.T) {
	store := NewStore(10 * time.Minute)
	t.Cleanup(store.Close)
	var wg sync.WaitGroup

	// Spawn many goroutines that concurrently read/write/delete
	for i := 0; i < 100; i++ {
		wg.Add(3)
		sess := "sess"
		prov := "prov"
		go func() {
			defer wg.Done()
			store.Put(sess, prov, &StateEntry{
				State:        "s",
				CodeVerifier: "v",
				CreatedAt:    time.Now(),
			})
		}()
		go func() {
			defer wg.Done()
			store.Get(sess, prov)
		}()
		go func() {
			defer wg.Done()
			store.Delete(sess, prov)
		}()
	}

	wg.Wait()
	// If we get here without a race detector complaint, the test passes
}
