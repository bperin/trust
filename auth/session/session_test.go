package session

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

func TestSession_CreateAndGet(t *testing.T) {
	t.Parallel()

	store := NewMemoryStore(0)
	defer store.Close()

	ctx := context.Background()
	userID := "user-123"
	data := map[string]any{"role": "admin", "email": "test@example.com"}

	sess, token, err := store.Create(ctx, userID, time.Hour, data)
	if err != nil {
		t.Fatalf("unexpected error creating session: %v", err)
	}

	if token == "" {
		t.Fatal("expected non-empty token")
	}
	if sess.UserID != userID {
		t.Errorf("expected userID %s, got %s", userID, sess.UserID)
	}
	if sess.Data["role"] != "admin" {
		t.Errorf("expected role admin, got %v", sess.Data["role"])
	}

	// Retrieve session
	retrieved, err := store.Get(ctx, token)
	if err != nil {
		t.Fatalf("unexpected error retrieving session: %v", err)
	}

	if retrieved.UserID != userID {
		t.Errorf("expected retrieved userID %s, got %s", userID, retrieved.UserID)
	}
	if retrieved.Data["email"] != "test@example.com" {
		t.Errorf("expected email test@example.com, got %v", retrieved.Data["email"])
	}
}

func TestSession_Expiration(t *testing.T) {
	t.Parallel()

	store := NewMemoryStore(0)
	defer store.Close()

	ctx := context.Background()
	// Create session that expires immediately (negative or zero TTL -> default or short)
	// We'll create with a very short TTL
	_, token, err := store.Create(ctx, userIDStub(), 1*time.Millisecond, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Wait for expiration
	time.Sleep(10 * time.Millisecond)

	_, err = store.Get(ctx, token)
	if !errors.Is(err, ErrSessionExpired) {
		t.Fatalf("expected ErrSessionExpired, got %v", err)
	}
}

func TestSession_Refresh(t *testing.T) {
	t.Parallel()

	store := NewMemoryStore(0)
	defer store.Close()

	ctx := context.Background()
	_, token, err := store.Create(ctx, "user-456", 50*time.Millisecond, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Wait a bit, then refresh
	time.Sleep(10 * time.Millisecond)

	refreshed, err := store.Refresh(ctx, token, time.Hour)
	if err != nil {
		t.Fatalf("unexpected error refreshing session: %v", err)
	}

	if time.Until(refreshed.ExpiresAt) < 30*time.Minute {
		t.Errorf("expected expiration to be extended, got ExpiresAt %v", refreshed.ExpiresAt)
	}

	// Retrieve to confirm
	_, err = store.Get(ctx, token)
	if err != nil {
		t.Fatalf("expected session to be valid after refresh, got %v", err)
	}
}

func TestSession_Delete(t *testing.T) {
	t.Parallel()

	store := NewMemoryStore(0)
	defer store.Close()

	ctx := context.Background()
	_, token, err := store.Create(ctx, "user-789", time.Hour, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	err = store.Delete(ctx, token)
	if err != nil {
		t.Fatalf("unexpected error deleting session: %v", err)
	}

	_, err = store.Get(ctx, token)
	if !errors.Is(err, ErrSessionNotFound) {
		t.Fatalf("expected ErrSessionNotFound, got %v", err)
	}
}

func TestSession_DeleteUserSessions(t *testing.T) {
	t.Parallel()

	store := NewMemoryStore(0)
	defer store.Close()

	ctx := context.Background()
	userID := "user-multi"
	_, token1, _ := store.Create(ctx, userID, time.Hour, nil)
	_, token2, _ := store.Create(ctx, userID, time.Hour, nil)
	_, tokenOther, _ := store.Create(ctx, "other-user", time.Hour, nil)

	err := store.DeleteUserSessions(ctx, userID)
	if err != nil {
		t.Fatalf("unexpected error deleting user sessions: %v", err)
	}

	if _, err := store.Get(ctx, token1); !errors.Is(err, ErrSessionNotFound) {
		t.Errorf("expected token1 to be deleted")
	}
	if _, err := store.Get(ctx, token2); !errors.Is(err, ErrSessionNotFound) {
		t.Errorf("expected token2 to be deleted")
	}
	if _, err := store.Get(ctx, tokenOther); err != nil {
		t.Errorf("expected other-user session to remain, got %v", err)
	}
}

func TestSession_BackgroundCleanup(t *testing.T) {
	t.Parallel()

	// Cleanup ticker every 10ms
	store := NewMemoryStore(10 * time.Millisecond)
	defer store.Close()

	ctx := context.Background()
	_, token, err := store.Create(ctx, "user-clean", 5*time.Millisecond, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Wait for expiration and cleanup tick
	time.Sleep(40 * time.Millisecond)

	store.mu.RLock()
	count := len(store.sessions)
	store.mu.RUnlock()

	if count != 0 {
		t.Errorf("expected expired session to be cleaned up, remaining sessions: %d", count)
	}

	_, err = store.Get(ctx, token)
	if !errors.Is(err, ErrSessionNotFound) && !errors.Is(err, ErrSessionExpired) {
		t.Errorf("expected session not found or expired, got %v", err)
	}
}

func TestSession_ConcurrencyAndRace(t *testing.T) {
	t.Parallel()

	store := NewMemoryStore(50 * time.Millisecond)
	defer store.Close()

	ctx := context.Background()
	var wg sync.WaitGroup
	workers := 20
	iterations := 100

	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			for j := 0; j < iterations; j++ {
				userID := "user-concurrent"
				sess, token, err := store.Create(ctx, userID, time.Second, map[string]any{"worker": workerID, "iter": j})
				if err != nil {
					continue
				}

				_, _ = store.Get(ctx, token)
				_, _ = store.Refresh(ctx, token, time.Second)
				if sess != nil {
					_ = store.Delete(ctx, token)
				}
			}
		}(i)
	}

	wg.Wait()
}

func TestSession_InvalidTokensAndContext(t *testing.T) {
	t.Parallel()

	store := NewMemoryStore(0)
	defer store.Close()

	cancelledCtx, cancel := context.WithCancel(context.Background())
	cancel()

	_, _, err := store.Create(cancelledCtx, "user-1", time.Hour, nil)
	if err == nil {
		t.Error("expected error with cancelled context on Create")
	}

	_, err = store.Get(context.Background(), "")
	if !errors.Is(err, ErrInvalidToken) {
		t.Errorf("expected ErrInvalidToken for empty token Get, got %v", err)
	}

	_, err = store.Get(cancelledCtx, "some-token")
	if err == nil {
		t.Error("expected error with cancelled context on Get")
	}

	err = store.Delete(context.Background(), "")
	if !errors.Is(err, ErrInvalidToken) {
		t.Errorf("expected ErrInvalidToken for empty token Delete, got %v", err)
	}
}

func userIDStub() string {
	return "user-stub"
}
