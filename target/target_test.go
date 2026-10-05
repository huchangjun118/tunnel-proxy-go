package target

import "testing"

func TestParseNormalization(t *testing.T) {
	cases := []struct {
		in   string
		port int
		want string
	}{
		{"localhost", 8080, "127.0.0.1:8080"},
		{"LOCALHOST", 8080, "127.0.0.1:8080"},
		{"127.0.0.1", 8080, "127.0.0.1:8080"},
		{"127.1", 8080, "127.0.0.1:8080"},
		{"::1", 8080, "127.0.0.1:8080"},
		{"[::1]", 8080, "127.0.0.1:8080"},
		{"2001:db8::1", 443, "[2001:db8::1]:443"},
		{"Example.COM.", 443, "example.com:443"},
	}
	for _, c := range cases {
		got, err := Parse(c.in, c.port)
		if err != nil {
			t.Fatalf("Parse(%q,%d): %v", c.in, c.port, err)
		}
		if got.Canonical() != c.want {
			t.Errorf("Parse(%q,%d) = %q, want %q", c.in, c.port, got.Canonical(), c.want)
		}
	}
}

func TestParseHostPort(t *testing.T) {
	got, err := ParseHostPort("LOCALHOST:80")
	if err != nil || got.Canonical() != "127.0.0.1:80" {
		t.Fatalf("got=%v err=%v", got, err)
	}
	if _, err := ParseHostPort("localhost"); err == nil {
		t.Fatal("expected error for missing port")
	}
	if _, err := Parse("localhost", 0); err == nil {
		t.Fatal("expected error for port 0")
	}
}
