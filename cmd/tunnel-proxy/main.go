// Command tunnel-proxy runs the forwarding proxy server.
//
// A single local TCP port multiplexes HTTP CONNECT and SOCKS5 sessions; the
// front-end protocol is selected from the first client byte. Every accepted
// session passes through the same authentication, ACL, concurrency-limit and
// relay pipeline.
package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/huchangjun118/tunnel-proxy-go"
)

type ruleFlag struct {
	rules *[]proxy.Rule
	deny  bool
}

func (f ruleFlag) String() string { return "" }

func (f ruleFlag) Set(v string) error {
	r, err := parseRule(v, f.deny)
	if err != nil {
		return err
	}
	*f.rules = append(*f.rules, r)
	return nil
}

func main() {
	var (
		listen        = flag.String("listen", "127.0.0.1:1080", "shared access address for CONNECT and SOCKS clients")
		user          = flag.String("user", "", "proxy-auth username (enables authentication when set)")
		pass          = flag.String("pass", "", "proxy-auth password")
		defaultDeny   = flag.Bool("default-deny", false, "deny targets not matched by an allow rule")
		maxTunnels    = flag.Int("max-tunnels", 64, "maximum concurrently open tunnels (0 => 1)")
		queue         = flag.Bool("queue", false, "queue new tunnels at capacity instead of rejecting")
		queueTimeout  = flag.Duration("queue-timeout", 5*time.Second, "max wait for a queued tunnel slot")
		dialTimeout   = flag.Duration("dial-timeout", 5*time.Second, "target connect timeout")
		handshakeTO   = flag.Duration("handshake-timeout", 10*time.Second, "front-end handshake timeout")
		idleTimeout   = flag.Duration("idle-timeout", 2*time.Minute, "per-tunnel idle timeout (0 disables)")
		halfCloseTO   = flag.Duration("half-close-timeout", 5*time.Second, "max drain time after one side half-closes")
		maxLifetime   = flag.Duration("max-lifetime", 10*time.Minute, "per-tunnel total lifetime (0 disables)")
		metricsPeriod = flag.Duration("metrics-period", 5*time.Second, "interval between metrics logs")
	)
	var allowRules, denyRules []proxy.Rule
	flag.Var(ruleFlag{rules: &allowRules}, "allow",
		"allow rule: host|suffix|CIDR[:port], repeatable (e.g. 127.0.0.1:8080 or 10.0.0.0/8)")
	flag.Var(ruleFlag{rules: &denyRules, deny: true}, "deny", "deny rule, same format as -allow")
	flag.Parse()

	cfg := proxy.DefaultConfig()
	cfg.Listen = *listen
	cfg.MaxTunnels = *maxTunnels
	if *queue {
		cfg.LimitPolicy = proxy.PolicyQueue
	}
	cfg.QueueTimeout = *queueTimeout
	cfg.DialTimeout = *dialTimeout
	cfg.HandshakeTimeout = *handshakeTO
	cfg.IdleTimeout = *idleTimeout
	cfg.HalfCloseTimeout = *halfCloseTO
	cfg.MaxLifetime = *maxLifetime

	if *user != "" {
		cfg.Auth.Enabled = true
		cfg.Auth.Credentials = map[string]string{*user: *pass}
	}
	cfg.ACL.DefaultDeny = *defaultDeny
	// Explicit deny rules take precedence over allow rules regardless of the
	// order flags were supplied on.
	cfg.ACL.Rules = append(append([]proxy.Rule{}, denyRules...), allowRules...)

	srv, err := proxy.NewServer(cfg)
	if err != nil {
		log.Fatalf("invalid config: %v", err)
	}

	ln, err := net.Listen("tcp", cfg.Listen)
	if err != nil {
		log.Fatalf("listen %s: %v", cfg.Listen, err)
	}
	log.Printf("tunnel-proxy listening on %s (auth=%v default-deny=%v max-tunnels=%d policy=%s)",
		ln.Addr(), cfg.Auth.Enabled, cfg.ACL.DefaultDeny, cfg.MaxTunnels, cfg.LimitPolicy)

	serveErr := make(chan error, 1)
	go func() { serveErr <- srv.Serve(ln) }()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	ticker := time.NewTicker(*metricsPeriod)
	defer ticker.Stop()
	for {
		select {
		case err := <-serveErr:
			if err != nil {
				log.Fatalf("serve: %v", err)
			}
			printMetrics(srv)
			return
		case <-ticker.C:
			printMetrics(srv)
		case sig := <-sigCh:
			log.Printf("received %s, shutting down", sig)
			_ = srv.Close()
			<-serveErr
			printMetrics(srv)
			return
		}
	}
}

// parseRule accepts "host", "host:port", "domain", "cidr" or "cidr:port".
// The port is only split off when the trailing colon component is numeric, so
// plain IPv6 hosts without brackets are left for net.ParseIP to reject.
func parseRule(spec string, deny bool) (proxy.Rule, error) {
	r := proxy.Rule{Action: proxy.ActionAllow}
	if deny {
		r.Action = proxy.ActionDeny
	}
	spec = strings.TrimSpace(spec)
	host := spec
	port := 0
	if i := strings.LastIndex(spec, ":"); i >= 0 && isDigits(spec[i+1:]) {
		host = strings.Trim(spec[:i], "[]")
		p, err := parsePort(spec[i+1:])
		if err != nil {
			return proxy.Rule{}, fmt.Errorf("bad rule %q: %w", spec, err)
		}
		port = p
	}
	if _, ipnet, err := net.ParseCIDR(host); err == nil {
		r.CIDR = ipnet
	} else {
		r.Host = host
	}
	r.Port = port
	return r, nil
}

func isDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

func parsePort(s string) (int, error) {
	var p int
	if _, err := fmt.Sscanf(s, "%d", &p); err != nil {
		return 0, err
	}
	if p < 1 || p > 65535 {
		return 0, fmt.Errorf("port out of range: %d", p)
	}
	return p, nil
}

func printMetrics(srv *proxy.Server) {
	m := srv.Metrics()
	log.Printf("metrics active=%d total=%d up=%d down=%d rejected=%v errors=%v",
		m.ActiveTunnels, m.TotalTunnels, m.BytesUp, m.BytesDown, m.Rejected, m.Errors)
}
