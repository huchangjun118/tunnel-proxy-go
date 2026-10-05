package config

import (
	"strings"
	"testing"
	"time"
)

func TestValidate(t *testing.T) {
	c := Default()
	if err := c.Validate(); err != nil {
		t.Fatalf("default invalid: %v", err)
	}

	bad := func(mut func(*Config)) error {
		c := Default()
		c.ListenAddr = "127.0.0.1:0"
		mut(c)
		return c.Validate()
	}
	if err := bad(func(c *Config) { c.ListenAddr = "" }); err == nil {
		t.Fatal("empty listen")
	}
	if err := bad(func(c *Config) {
		c.AuthEnabled = true
		c.Credentials = map[string]string{}
	}); err == nil {
		t.Fatal("auth without creds")
	}
	if err := bad(func(c *Config) {
		c.AuthEnabled = true
		c.Credentials = map[string]string{"": "x"}
	}); err == nil {
		t.Fatal("empty user")
	}
	if err := bad(func(c *Config) { c.AllowedPorts = []int{70000} }); err == nil {
		t.Fatal("bad port")
	}
	if err := bad(func(c *Config) { c.IdleTimeout = -time.Second }); err == nil {
		t.Fatal("negative timeout")
	}
	if err := bad(func(c *Config) {
		c.Overflow = OverflowQueue
		c.QueueTimeout = 0
	}); err == nil || !strings.Contains(err.Error(), "queue") {
		t.Fatalf("queue without timeout: %v", err)
	}
}
