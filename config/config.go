package config

import (
	"errors"
	"time"
)

// OverflowPolicy defines behavior when the tunnel limit is reached.
type OverflowPolicy int

const (
	// OverflowReject rejects new tunnels immediately when at capacity.
	OverflowReject OverflowPolicy = iota
	// OverflowQueue lets new tunnels wait for a free slot up to QueueTimeout.
	OverflowQueue
)

// Config holds all configurable options for the proxy server.
type Config struct {
	// ListenAddr is the single access endpoint shared by CONNECT and SOCKS5.
	ListenAddr string

	// Auth
	AuthEnabled bool
	Credentials map[string]string // username -> password

	// Access control. Empty host list means "any host allowed";
	// empty port list means "any port allowed".
	AllowedHosts []string
	AllowedPorts []int

	// Resource limits. MaxTunnels <= 0 means unlimited.
	MaxTunnels   int
	IdleTimeout  time.Duration // no data transfer in either direction
	TotalTimeout time.Duration // maximum lifetime of a tunnel
	Overflow     OverflowPolicy
	QueueTimeout time.Duration // max wait for a slot when queuing

	// DialTimeout bounds target connect (and name resolution via resolver).
	DialTimeout time.Duration

	// IOBufferBytes is the relay buffer size per direction.
	IOBufferBytes int

	// MetricsAddr exposes a JSON stats endpoint; "" disables it.
	MetricsAddr string
}

// Default returns a config with safe local-only defaults.
func Default() *Config {
	return &Config{
		ListenAddr:    "127.0.0.1:18080",
		AuthEnabled:   false,
		Credentials:   map[string]string{},
		AllowedHosts:  nil,
		AllowedPorts:  nil,
		MaxTunnels:    1024,
		IdleTimeout:   2 * time.Minute,
		TotalTimeout:  10 * time.Minute,
		Overflow:      OverflowReject,
		QueueTimeout:  5 * time.Second,
		DialTimeout:   5 * time.Second,
		IOBufferBytes: 32 * 1024,
		MetricsAddr:   "127.0.0.1:18081",
	}
}

// Validate checks the config and returns an error describing the first
// invalid field it finds.
func (c *Config) Validate() error {
	if c.ListenAddr == "" {
		return errors.New("config: ListenAddr must not be empty")
	}
	if c.AuthEnabled && len(c.Credentials) == 0 {
		return errors.New("config: auth enabled but no credentials configured")
	}
	for user, pass := range c.Credentials {
		if user == "" || pass == "" {
			return errors.New("config: credentials must have non-empty username and password")
		}
	}
	for _, p := range c.AllowedPorts {
		if p <= 0 || p > 65535 {
			return errors.New("config: allowed port out of range")
		}
	}
	if c.IdleTimeout < 0 || c.TotalTimeout < 0 || c.DialTimeout < 0 || c.QueueTimeout < 0 {
		return errors.New("config: timeouts must not be negative")
	}
	if c.IOBufferBytes < 0 {
		return errors.New("config: IOBufferBytes must not be negative")
	}
	if c.Overflow == OverflowQueue && c.QueueTimeout == 0 {
		return errors.New("config: queue policy requires a positive QueueTimeout")
	}
	return nil
}
