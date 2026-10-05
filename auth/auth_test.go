package auth

import "testing"

func TestCheck(t *testing.T) {
	a := New(true, map[string]string{"alice": "s3cret"})
	if r := a.Check("alice", "s3cret"); r != AuthOK {
		t.Fatalf("valid creds: %v", r)
	}
	if r := a.Check("", ""); r != AuthMissing {
		t.Fatalf("missing creds: %v", r)
	}
	if r := a.Check("alice", "wrong"); r != AuthInvalid {
		t.Fatalf("bad password: %v", r)
	}
	if r := a.Check("bob", "s3cret"); r != AuthInvalid {
		t.Fatalf("unknown user: %v", r)
	}
}

func TestDisabled(t *testing.T) {
	a := New(false, nil)
	if r := a.Check("", ""); r != AuthDisabled {
		t.Fatalf("disabled auth: %v", r)
	}
	if a.Enabled() {
		t.Fatal("enabled mismatch")
	}
}
