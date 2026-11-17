package main

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	pp "go.vitalvas.com/kasper/privacypass"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
)

func TestPublicIdentityLocalTransport(t *testing.T) {
	b, err := os.ReadFile("../../common/test-fixtures/privacy-pass/rfc9578-a2.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Vectors []struct {
			Key string `json:"pkI"`
		} `json:"vectors"`
	}
	if err := json.Unmarshal(b, &fixture); err != nil {
		t.Fatal(err)
	}
	spki, err := hex.DecodeString(fixture.Vectors[0].Key)
	if err != nil {
		t.Fatal(err)
	}
	c := &pp.TokenChallenge{TokenType: 2, IssuerName: "issuer.test", OriginInfo: "origin.test", RedemptionContext: make([]byte, 32)}
	cb, err := c.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	var issued atomic.Bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/private-token-issuer-directory":
			fmt.Fprintf(w, `{"issuer-request-uri":"https://issuer.test/private-token/issue","token-keys":[{"token-type":2,"token-key":%q}]}`, base64.URLEncoding.EncodeToString(spki))
		case "/private-token/protected":
			w.Header().Set("WWW-Authenticate", fmt.Sprintf(`PrivateToken challenge="%s", token-key="%s", max-age=60`, base64.URLEncoding.EncodeToString(cb), base64.URLEncoding.EncodeToString(spki)))
			w.WriteHeader(401)
		case "/private-token/issue":
			issued.Store(true)
			// Stop after proving that issuance uses local transport.
			w.WriteHeader(400)
		default:
			w.WriteHeader(404)
		}
	}))
	defer server.Close()
	invitation := filepath.Join(t.TempDir(), "invitation")
	if err := os.WriteFile(invitation, []byte("test-admission"), 0600); err != nil {
		t.Fatal(err)
	}
	err = client(server.URL, server.URL, invitation)
	if !issued.Load() || err == nil || err.Error() != "issuance response" {
		t.Fatalf("local issuance not reached: %v", err)
	}
}

func TestRFCVectors(t *testing.T) {
	b, e := os.ReadFile("../../common/test-fixtures/privacy-pass/rfc9578-a2.json")
	if e != nil {
		t.Fatal(e)
	}
	var fixture struct {
		Vectors []map[string]json.RawMessage `json:"vectors"`
	}
	if e = json.Unmarshal(b, &fixture); e != nil {
		t.Fatal(e)
	}
	for _, v := range fixture.Vectors {
		field := func(name string) []byte {
			var s string
			if e := json.Unmarshal(v[name], &s); e != nil {
				t.Fatal(e)
			}
			b, e := hex.DecodeString(s)
			if e != nil {
				t.Fatal(e)
			}
			return b
		}
		spki := field("pkI")
		if _, e := key(spki); e != nil {
			t.Fatal(e)
		}
		if _, e := key(append(append([]byte{}, spki...), 0)); e == nil {
			t.Fatal("accepted trailing SPKI")
		}
		cb := field("token_challenge")
		if _, e := challenge(cb); e != nil {
			t.Fatal(e)
		}
		if _, e := challenge(append(append([]byte{}, cb...), 0)); e == nil {
			t.Fatal("accepted trailing challenge")
		}
		for name, n := range map[string]int{"token_request": 259, "token_response": 256, "token": 354} {
			if len(field(name)) != n {
				t.Fatal(name, "length")
			}
		}
		tok, e := pp.UnmarshalToken(field("token"))
		if e != nil {
			t.Fatal(e)
		}
		out, e := tok.Marshal()
		if e != nil || !bytes.Equal(out, field("token")) {
			t.Fatal("token roundtrip")
		}
		dir := t.TempDir()
		for name, data := range map[string][]byte{"spki.der": spki, "challenge.bin": cb, "token.bin": out} {
			if e := os.WriteFile(filepath.Join(dir, name), data, 0600); e != nil {
				t.Fatal(e)
			}
		}
		if e := verify(dir); e != nil {
			t.Fatal(e)
		}
	}
}

func TestLoopbackOnly(t *testing.T) {
	for _, s := range []string{"http://localhost:80", "https://127.0.0.1", "http://192.0.2.1", "http://127.0.0.1/path", "http://user@127.0.0.1"} {
		if _, e := base(s); e == nil {
			t.Fatal("accepted endpoint")
		}
	}
	for _, s := range []string{"http://127.0.0.1:8080", "http://[::1]:8080"} {
		if _, e := base(s); e != nil {
			t.Fatal(e)
		}
	}
}
