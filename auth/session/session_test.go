package session

import (
	"context"
	"errors"
	"testing"
	"time"
)

// fakeStore is a minimal Store implementation for interface contract
// testing. It is not shipped — trust is stateless.
type fakeStore struct {
	sessions map[string]*Session
}

func newFakeStore() *fakeStore {
	return &fakeStore{sessions: make(map[string]*Session)}
}

func (f *fakeStore) Create(_ context.Context, userID string, ttl time.Duration, data map[string]any) (*Session, string, error) {
	token := "fake-token-" + userID
	sess := &Session{
		ID:        token,
		UserID:    userID,
		Data:      data,
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(ttl),
	}
	f.sessions[token] = sess
	return sess, token, nil
}

func (f *fakeStore) Get(_ context.Context, token string) (*Session, error) {
	sess, ok := f.sessions[token]
	if !ok {
		return nil, ErrSessionNotFound
	}
	return sess, nil
}

func (f *fakeStore) Refresh(_ context.Context, token string, ttl time.Duration) (*Session, error) {
	sess, ok := f.sessions[token]
	if !ok {
		return nil, ErrSessionNotFound
	}
	sess.ExpiresAt = time.Now().Add(ttl)
	return sess, nil
}

func (f *fakeStore) Delete(_ context.Context, token string) error {
	delete(f.sessions, token)
	return nil
}

func (f *fakeStore) DeleteUserSessions(_ context.Context, userID string) error {
	for token, sess := range f.sessions {
		if sess.UserID == userID {
			delete(f.sessions, token)
		}
	}
	return nil
}

func (f *fakeStore) Close() error { return nil }

// Compile-time assertion that fakeStore satisfies Store.
var _ Store = (*fakeStore)(nil)

func TestStoreInterface(t *testing.T) {
	t.Parallel()

	store := newFakeStore()
	ctx := context.Background()

	// Create
	sess, token, err := store.Create(ctx, "user-1", time.Hour, map[string]any{"role": "admin"})
	if err != nil {
		t.Fatalf("Create failed: %v", err)
	}
	if token == "" {
		t.Fatal("Create returned empty token")
	}
	if sess.UserID != "user-1" {
		t.Fatalf("Create UserID = %s, want user-1", sess.UserID)
	}

	// Get
	got, err := store.Get(ctx, token)
	if err != nil {
		t.Fatalf("Get failed: %v", err)
	}
	if got.UserID != "user-1" {
		t.Fatalf("Get UserID = %s, want user-1", got.UserID)
	}

	// Get not found
	_, err = store.Get(ctx, "nonexistent")
	if !errors.Is(err, ErrSessionNotFound) {
		t.Fatalf("Get nonexistent err = %v, want ErrSessionNotFound", err)
	}

	// Refresh
	_, err = store.Refresh(ctx, token, 2*time.Hour)
	if err != nil {
		t.Fatalf("Refresh failed: %v", err)
	}

	// Delete
	if err := store.Delete(ctx, token); err != nil {
		t.Fatalf("Delete failed: %v", err)
	}
	_, err = store.Get(ctx, token)
	if !errors.Is(err, ErrSessionNotFound) {
		t.Fatalf("Get after Delete err = %v, want ErrSessionNotFound", err)
	}

	// DeleteUserSessions
	_, _, _ = store.Create(ctx, "user-2", time.Hour, nil)
	_, _, _ = store.Create(ctx, "user-2", time.Hour, nil)
	if err := store.DeleteUserSessions(ctx, "user-2"); err != nil {
		t.Fatalf("DeleteUserSessions failed: %v", err)
	}

	// Close
	if err := store.Close(); err != nil {
		t.Fatalf("Close failed: %v", err)
	}
}
