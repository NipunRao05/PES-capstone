// Package state provides durable scaling-agent state storage.
package state

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/scalingagent/internal/scaler"
)

var ErrNotFound = errors.New("scaling state not found")

// RedisStore persists one versioned operational-state document without a TTL.
type RedisStore struct {
	client  *redis.Client
	key     string
	timeout time.Duration
}

func NewRedisStore(addr, password string, db int, key string, timeout time.Duration) *RedisStore {
	if key == "" {
		key = "capstone:scaling-agent:state:v1"
	}
	if timeout <= 0 {
		timeout = time.Second
	}
	return &RedisStore{
		client: redis.NewClient(&redis.Options{
			Addr:         addr,
			Password:     password,
			DB:           db,
			DialTimeout:  timeout,
			ReadTimeout:  timeout,
			WriteTimeout: timeout,
		}),
		key:     key,
		timeout: timeout,
	}
}

func (s *RedisStore) Key() string { return s.key }

func (s *RedisStore) Ping() error {
	ctx, cancel := context.WithTimeout(context.Background(), s.timeout)
	defer cancel()
	return s.client.Ping(ctx).Err()
}

func (s *RedisStore) Load() (scaler.PersistentState, error) {
	ctx, cancel := context.WithTimeout(context.Background(), s.timeout)
	defer cancel()
	raw, err := s.client.Get(ctx, s.key).Bytes()
	if errors.Is(err, redis.Nil) {
		return scaler.PersistentState{}, ErrNotFound
	}
	if err != nil {
		return scaler.PersistentState{}, fmt.Errorf("read scaling state: %w", err)
	}
	var persisted scaler.PersistentState
	if err := json.Unmarshal(raw, &persisted); err != nil {
		return scaler.PersistentState{}, fmt.Errorf("decode scaling state: %w", err)
	}
	return persisted, nil
}

func (s *RedisStore) Save(persisted scaler.PersistentState) error {
	persisted.Version = scaler.PersistentStateVersion
	persisted.SavedAt = time.Now().UTC()
	raw, err := json.Marshal(persisted)
	if err != nil {
		return fmt.Errorf("encode scaling state: %w", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), s.timeout)
	defer cancel()
	if err := s.client.Set(ctx, s.key, raw, 0).Err(); err != nil {
		return fmt.Errorf("write scaling state: %w", err)
	}
	return nil
}

func (s *RedisStore) Close() error { return s.client.Close() }
