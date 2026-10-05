// Command tproxy runs a local forwarding proxy that serves HTTP CONNECT
// and SOCKS5 on one access address. Everything stays in-process and on
// loopback, so the whole chain is reproducible without external
// services.
package main

import (
	"context"
	"flag"
	"log"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/huchangjun118/tunnel-proxy-go/config"
	"github.com/huchangjun118/tunnel-proxy-go/server"
)

func main() {
	cfg := parseFlags()
	if err := cfg.Validate(); err != nil {
		log.Fatalf("invalid config: %v", err)
	}

	srv, err := server.New(cfg)
	if err != nil {
		log.Fatalf("server init: %v", err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	go func() {
		log.Printf("tproxy listening on %s (CONNECT + SOCKS5)", cfg.ListenAddr)
		if cfg.MetricsAddr != "" {
			log.Printf("metrics on http://%s/metrics", cfg.MetricsAddr)
		}
		if err := srv.ListenAndServe(ctx); err != nil {
			log.Printf("serve stopped: %v", err)
			stop()
		}
	}()

	<-ctx.Done()
	log.Printf("shutting down ...")
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		log.Printf("shutdown: %v", err)
		os.Exit(1)
	}
	log.Printf("stopped")
}

func parseFlags() *config.Config {
	cfg := config.Default()

	listen := flag.String("listen", cfg.ListenAddr, "access address serving CONNECT and SOCKS5")
	metrics := flag.String("metrics", cfg.MetricsAddr, "metrics HTTP address (empty to disable)")
	user := flag.String("user", "", "proxy credentials in user:pass form; repeatable, comma separated")
	hosts := flag.String("allow-hosts", "", "comma-separated allowed host names/IPs/suffixes (.example.com); empty=all")
	ports := flag.String("allow-ports", "", "comma-separated allowed TCP ports; empty=all")
	maxTunnels := flag.Int("max-tunnels", cfg.MaxTunnels, "max concurrent tunnels (<=0 unlimited)")
	idle := flag.Duration("idle-timeout", cfg.IdleTimeout, "per-tunnel idle timeout")
	total := flag.Duration("total-timeout", cfg.TotalTimeout, "max tunnel lifetime")
	dialTO := flag.Duration("dial-timeout", cfg.DialTimeout, "target dial timeout")
	policy := flag.String("overflow", "reject", "behavior at capacity: reject or queue")
	queueTO := flag.Duration("queue-timeout", cfg.QueueTimeout, "max queue wait when overflow=queue")
	bufKB := flag.Int("buf-kb", cfg.IOBufferBytes/1024, "relay buffer size in KiB")
	flag.Parse()

	cfg.ListenAddr = *listen
	cfg.MetricsAddr = *metrics
	cfg.MaxTunnels = *maxTunnels
	cfg.IdleTimeout = *idle
	cfg.TotalTimeout = *total
	cfg.DialTimeout = *dialTO
	cfg.QueueTimeout = *queueTO
	cfg.IOBufferBytes = *bufKB * 1024

	if *user != "" {
		cfg.AuthEnabled = true
		cfg.Credentials = map[string]string{}
		for _, pair := range strings.Split(*user, ",") {
			u, p, ok := strings.Cut(strings.TrimSpace(pair), ":")
			if !ok {
				log.Fatalf("bad credential %q, want user:pass", pair)
			}
			cfg.Credentials[u] = p
		}
	}
	if *hosts != "" {
		for _, h := range strings.Split(*hosts, ",") {
			if h = strings.TrimSpace(h); h != "" {
				cfg.AllowedHosts = append(cfg.AllowedHosts, h)
			}
		}
	}
	if *ports != "" {
		for _, p := range strings.Split(*ports, ",") {
			n, err := strconv.Atoi(strings.TrimSpace(p))
			if err != nil {
				log.Fatalf("bad port %q: %v", p, err)
			}
			cfg.AllowedPorts = append(cfg.AllowedPorts, n)
		}
	}
	switch *policy {
	case "reject":
		cfg.Overflow = config.OverflowReject
	case "queue":
		cfg.Overflow = config.OverflowQueue
	default:
		log.Fatalf("unknown overflow policy %q", *policy)
	}
	return cfg
}
