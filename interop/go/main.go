// This program checks interoperability with an independent implementation of RFC 9577 and RFC 9578.
// It limits diagnostic output to avoid exposing credentials.
package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"time"

	"github.com/cloudflare/pat-go/tokens/type2"
	"github.com/cloudflare/pat-go/util"
	pp "go.vitalvas.com/kasper/privacypass"
)

func key(b []byte) (*rsa.PublicKey, error) {
	if len(b) < 256 || len(b) > 1024 {
		return nil, errors.New("SPKI length")
	}
	p, e := util.UnmarshalTokenKey(b)
	if e != nil {
		return nil, errors.New("SPKI parse")
	}
	canonical, e := util.MarshalTokenKeyPSSOID(p)
	if e != nil || !bytes.Equal(b, canonical) {
		return nil, errors.New("noncanonical SPKI")
	}
	other, e := pp.MarshalPublicKey(p)
	if e != nil || !bytes.Equal(b, other) {
		return nil, errors.New("Kasper SPKI mismatch")
	}
	id, e := pp.TokenKeyID(p)
	want := sha256.Sum256(b)
	if e != nil || !bytes.Equal(id, want[:]) {
		return nil, errors.New("key ID mismatch")
	}
	return p, nil
}
func challenge(b []byte) (*pp.TokenChallenge, error) {
	c, e := pp.UnmarshalTokenChallenge(b)
	if e != nil {
		return nil, errors.New("challenge parse")
	}
	out, e := c.Marshal()
	if e != nil || !bytes.Equal(b, out) {
		return nil, errors.New("challenge roundtrip")
	}
	return c, nil
}
func readBounded(r io.Reader, n int64) ([]byte, error) {
	b, e := io.ReadAll(io.LimitReader(r, n+1))
	if e != nil || int64(len(b)) > n {
		return nil, errors.New("bounded read failed")
	}
	return b, nil
}
func file(p string, n int64) ([]byte, error) {
	f, e := os.Open(p)
	if e != nil {
		return nil, errors.New("input file unavailable")
	}
	defer f.Close()
	return readBounded(f, n)
}
func verify(dir string) error {
	b, e := file(filepath.Join(dir, "spki.der"), 1024)
	if e != nil {
		return e
	}
	p, e := key(b)
	if e != nil {
		return e
	}
	cb, e := file(filepath.Join(dir, "challenge.bin"), 131104)
	if e != nil {
		return e
	}
	c, e := challenge(cb)
	if e != nil {
		return e
	}
	tb, e := file(filepath.Join(dir, "token.bin"), 354)
	if e != nil {
		return e
	}
	if len(tb) != 354 {
		return errors.New("token length")
	}
	t, e := pp.UnmarshalToken(tb)
	if e != nil {
		return errors.New("token parse")
	}
	cache := pp.NewMemoryNonceCache()
	if e = pp.VerifyToken(context.Background(), p, c, t, cache, 0); e != nil {
		return errors.New("Kasper verification failed")
	}
	if !errors.Is(pp.VerifyToken(context.Background(), p, c, t, cache, 0), pp.ErrReplay) {
		return errors.New("replay accepted")
	}
	wrong := *c
	wrong.OriginInfo += ".wrong"
	if !errors.Is(pp.VerifyToken(context.Background(), p, &wrong, t, pp.NewMemoryNonceCache(), 0), pp.ErrChallengeMismatch) {
		return errors.New("challenge mismatch accepted")
	}
	id := sha256.Sum256(b)
	fmt.Printf("key_id=%x verify=ok replay=rejected wrong_challenge=rejected\n", id)
	return nil
}
func base(s string) (*url.URL, error) {
	u, e := url.Parse(s)
	if e != nil {
		return nil, errors.New("invalid endpoint")
	}
	ip := net.ParseIP(u.Hostname())
	if u.Scheme != "http" || ip == nil || !ip.IsLoopback() || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") {
		return nil, errors.New("numeric loopback HTTP required")
	}
	u.Path = ""
	return u, nil
}

var authPattern = regexp.MustCompile(`^PrivateToken challenge="([A-Za-z0-9_=-]+)", token-key="([A-Za-z0-9_=-]+)", max-age=([0-9]+)$`)

func decode(s string) ([]byte, error) {
	b, e := base64.URLEncoding.Strict().DecodeString(s)
	if e != nil || base64.URLEncoding.EncodeToString(b) != s {
		return nil, errors.New("noncanonical base64url")
	}
	return b, nil
}
func client(issuer, origin, invitation string) error {
	i, e := base(issuer)
	if e != nil {
		return e
	}
	o, e := base(origin)
	if e != nil {
		return e
	}
	admission, e := file(invitation, 8192)
	if e != nil {
		return e
	}
	admission = bytes.TrimSpace(admission)
	if len(admission) == 0 || bytes.ContainsAny(admission, "\r\n") {
		return errors.New("invalid invitation")
	}
	h := &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{Proxy: nil, DialContext: (&net.Dialer{Timeout: 5 * time.Second}).DialContext, DisableKeepAlives: true}, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	defer h.CloseIdleConnections()
	get := func(method, endpoint string, body []byte, headers map[string]string) (int, http.Header, []byte, error) {
		req, e := http.NewRequest(method, endpoint, bytes.NewReader(body))
		if e != nil {
			return 0, nil, nil, errors.New("request construction")
		}
		for k, v := range headers {
			req.Header.Set(k, v)
		}
		resp, e := h.Do(req)
		if e != nil {
			return 0, nil, nil, errors.New("HTTP request failed")
		}
		defer resp.Body.Close()
		b, e := readBounded(resp.Body, 65536)
		return resp.StatusCode, resp.Header, b, e
	}
	status, _, db, e := get("GET", i.String()+"/.well-known/private-token-issuer-directory", nil, nil)
	if e != nil {
		return e
	}
	if status != 200 {
		return errors.New("directory status")
	}
	var d struct {
		URI  string `json:"issuer-request-uri"`
		Keys []struct {
			Type int    `json:"token-type"`
			Key  string `json:"token-key"`
		} `json:"token-keys"`
	}
	if json.Unmarshal(db, &d) != nil || d.URI != "https://issuer.test/private-token/issue" {
		return errors.New("directory identity")
	}
	status, headers, _, e := get("GET", o.String()+"/private-token/protected", nil, nil)
	if e != nil {
		return e
	}
	values := headers.Values("WWW-Authenticate")
	if status != 401 || len(values) != 1 {
		return errors.New("origin challenge status")
	}
	m := authPattern.FindStringSubmatch(values[0])
	if m == nil {
		return errors.New("challenge header")
	}
	cb, e := decode(m[1])
	if e != nil {
		return e
	}
	spki, e := decode(m[2])
	if e != nil {
		return e
	}
	found := false
	for _, k := range d.Keys {
		if k.Type == 2 && k.Key == m[2] {
			found = true
		}
	}
	if !found {
		return errors.New("directory key mismatch")
	}
	p, e := key(spki)
	if e != nil {
		return e
	}
	c, e := challenge(cb)
	if e != nil {
		return e
	}
	if c.IssuerName != "issuer.test" || c.OriginInfo != "origin.test" || len(c.RedemptionContext) != 32 {
		return errors.New("challenge identity")
	}
	nonce := make([]byte, 32)
	if _, e = rand.Read(nonce); e != nil {
		return errors.New("randomness failed")
	}
	id := sha256.Sum256(spki)
	state, e := type2.NewBasicPublicClient().CreateTokenRequest(cb, nonce, id[:], p)
	if e != nil {
		return errors.New("request creation")
	}
	request := state.Request().Marshal()
	if len(request) != 259 {
		return errors.New("request length")
	}
	// Send the request to the validated loopback address to keep issuance local.
	status, _, response, e := get("POST", i.String()+"/private-token/issue", request, map[string]string{"Freebird-Admission": string(admission), "Content-Type": "application/private-token-request"})
	if e != nil {
		return e
	}
	if status != 200 || len(response) != 256 {
		return errors.New("issuance response")
	}
	token, e := state.FinalizeToken(response)
	if e != nil {
		return errors.New("finalization")
	}
	wire := token.Marshal()
	if len(wire) != 354 {
		return errors.New("token length")
	}
	auth := map[string]string{"Authorization": `PrivateToken token="` + base64.URLEncoding.EncodeToString(wire) + `"`}
	status, _, _, e = get("GET", o.String()+"/private-token/protected", nil, auth)
	if e != nil {
		return e
	}
	if status != 200 {
		return errors.New("redemption failed")
	}
	status, _, _, e = get("GET", o.String()+"/private-token/protected", nil, auth)
	if e != nil {
		return e
	}
	if status != 401 {
		return errors.New("replay accepted")
	}
	fmt.Printf("key_id=%x issuance=ok redemption=ok replay=rejected\n", id)
	return nil
}
func main() {
	var e error
	switch {
	case len(os.Args) == 3 && os.Args[1] == "verify":
		e = verify(os.Args[2])
	case len(os.Args) == 5 && os.Args[1] == "client":
		e = client(os.Args[2], os.Args[3], os.Args[4])
	default:
		e = errors.New("usage: verify OUTPUT_DIR | client ISSUER_HTTP_BASE ORIGIN_HTTP_BASE INVITATION_FILE")
	}
	if e != nil {
		fmt.Fprintln(os.Stderr, e)
		os.Exit(1)
	}
}
