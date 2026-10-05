package e2e

import (
	"bufio"
	"encoding/base64"
	"io"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/huchangjun118/tunnel-proxy-go/config"
	"github.com/huchangjun118/tunnel-proxy-go/testutil"
)

// TestSocksDomainName verifies ATYP=0x03 domain targets are resolved,
// normalized and tunneled identically to IP targets.
func TestSocksDomainName(t *testing.T) {
	echo := testutil.StartEcho(t)
	_, port, _ := net.SplitHostPort(echo.Addr())
	srv := testutil.StartProxy(t, nil)

	c, rep := testutil.DialSOCKS5(t, srv.Addr().String(), "localhost:"+port, "", "")
	defer c.Close()
	if rep != 0 {
		t.Fatalf("rep=%d", rep)
	}
	roundTrip(t, c, "domain-tunnel\n")
}

// TestConnectPipelinedPayload sends tunnel payload in the same TCP
// segment as the CONNECT request + auth header; it must not be lost.
func TestConnectPipelinedPayload(t *testing.T) {
	echo := testutil.StartEcho(t)
	srv := testutil.StartProxy(t, func(c *config.Config) {
		c.AuthEnabled = true
		c.Credentials = map[string]string{"u": "p"}
	})
	raw, err := net.Dial("tcp", srv.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	token := base64.StdEncoding.EncodeToString([]byte("u:p"))
	req := "CONNECT " + echo.Addr() + " HTTP/1.1\r\nHost: " + echo.Addr() + "\r\n" +
		"Proxy-Authorization: Basic " + token + "\r\n\r\nPIPELINED-PAYLOAD\n"
	if _, err := raw.Write([]byte(req)); err != nil {
		t.Fatal(err)
	}
	raw.SetReadDeadline(time.Now().Add(3 * time.Second))
	br := bufio.NewReader(raw)
	resp, err := http.ReadResponse(br, &http.Request{Method: "CONNECT"})
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("resp=%v err=%v", resp, err)
	}
	buf := make([]byte, len("PIPELINED-PAYLOAD\n"))
	if _, err := io.ReadFull(br, buf); err != nil {
		t.Fatalf("pipelined payload lost: %v", err)
	}
	if string(buf) != "PIPELINED-PAYLOAD\n" {
		t.Fatalf("got %q", buf)
	}
}

// TestProtocolEquivalence runs the same authenticated echo exchange over
// both protocols and asserts identical byte accounting outcomes.
func TestProtocolEquivalence(t *testing.T) {
	echo := testutil.StartEcho(t)
	srv := testutil.StartProxy(t, func(c *config.Config) {
		c.AuthEnabled = true
		c.Credentials = map[string]string{"u": "p"}
	})
	msg := "equivalence-check-12345\n"

	run := func(t *testing.T, proto string) {
		var c net.Conn
		if proto == "connect" {
			var resp *http.Response
			c, resp = testutil.DialCONNECT(t, srv.Addr().String(), echo.Addr(), "u", "p")
			if resp.StatusCode != http.StatusOK {
				t.Fatal(resp.Status)
			}
		} else {
			var rep byte
			c, rep = testutil.DialSOCKS5(t, srv.Addr().String(), echo.Addr(), "u", "p")
			if rep != 0 {
				t.Fatalf("rep=%d", rep)
			}
		}
		defer c.Close()
		roundTrip(t, c, msg)
	}

	before := srv.Stats()
	t.Run("connect", func(t *testing.T) { run(t, "connect") })
	mid := srv.Stats()
	up1 := mid.BytesClientToTarget - before.BytesClientToTarget
	down1 := mid.BytesTargetToClient - before.BytesTargetToClient
	t.Run("socks5", func(t *testing.T) { run(t, "socks5") })
	after := srv.Stats()
	up2 := after.BytesClientToTarget - mid.BytesClientToTarget
	down2 := after.BytesTargetToClient - mid.BytesTargetToClient
	if up1 != up2 || down1 != down2 || up1 != int64(len(msg)) || down1 != int64(len(msg)) {
		t.Fatalf("byte accounting differs: connect up/down=%d/%d socks up/down=%d/%d msg=%d",
			up1, down1, up2, down2, len(msg))
	}
	waitFor(t, func() bool { return srv.Stats().ActiveTunnels == 0 }, 3*time.Second)
}
