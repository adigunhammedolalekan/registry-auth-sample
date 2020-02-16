package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/docker/distribution/registry/auth/token"
	"github.com/docker/libtrust"
	"log"
	"math/rand"
	"net/http"
	"os"
	"strings"
	"time"
)

func main() {
	crt, key := "/mnt/certs/RootCA.crt", "/mnt/certs/RootCA.key"
	tk, err := newTokenServer(crt, key)
	if err != nil {
		log.Fatal(err)
	}
	if err := tk.run(); err != nil {
		log.Fatal(err)
	}
}

type Option struct {
	issuer, typ, name, account, service string
	actions                             []string // requested actions
}
type Token struct {
	Token       string `json:"token"`
	AccessToken string `json:"access_token"`
}

type tokenServer struct {
	privateKey libtrust.PrivateKey
	pubKey     libtrust.PublicKey
	crt, key   string
}

func newTokenServer(crt, key string) (*tokenServer, error) {
	pk, prk, err := loadCertAndKey(crt, key)
	if err != nil {
		return nil, err
	}
	t := &tokenServer{privateKey: prk, pubKey: pk, crt: crt, key: key}
	return t, nil
}

func (srv *tokenServer) createToken(opt *Option, actions []string) (*Token, error) {
	// sign any string to get the used signing Algorithm for the private key
	_, algo, err := srv.privateKey.Sign(strings.NewReader("AUTH"), 0)
	if err != nil {
		return nil, err
	}
	header := token.Header{
		Type:       "JWT",
		SigningAlg: algo,
		KeyID:      srv.pubKey.KeyID(),
	}
	headerJson, err := json.Marshal(header)
	if err != nil {
		return nil, err
	}
	now := time.Now().Unix()
	exp := now + time.Now().Add(24*time.Hour).Unix()
	claim := token.ClaimSet{
		Issuer:     opt.issuer,
		Subject:    opt.account,
		Audience:   opt.service,
		Expiration: exp,
		NotBefore:  now - 10,
		IssuedAt:   now,
		JWTID:      fmt.Sprintf("%d", rand.Int63()),
		Access:     []*token.ResourceActions{},
	}
	claim.Access = append(claim.Access, &token.ResourceActions{
		Type:    opt.typ,
		Name:    opt.name,
		Actions: actions,
	})
	claimJson, err := json.Marshal(claim)
	if err != nil {
		return nil, err
	}
	payload := fmt.Sprintf("%s%s%s", encodeBase64(headerJson), token.TokenSeparator, encodeBase64(claimJson))
	sig, sigAlgo, err := srv.privateKey.Sign(strings.NewReader(payload), 0)
	if err != nil && sigAlgo != algo {
		return nil, err
	}
	tk := fmt.Sprintf("%s%s%s", payload, token.TokenSeparator, encodeBase64(sig))
	return &Token{Token: tk, AccessToken: tk}, nil
}

func (srv *tokenServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	username, password, ok := r.BasicAuth()
	if !ok {
		http.Error(w, "auth credentials not found", http.StatusUnauthorized)
		return
	}
	// compare username and password against your datasets
	// our example only allows foo:bar
	if username != "foo" || password != "bar" {
		http.Error(w, "invalid auth credentials", http.StatusUnauthorized)
		return
	}
	// do authorization check
	opt := srv.createTokenOption(r)
	actions := srv.authorize(opt)
	tk, err := srv.createToken(opt, actions)
	if err != nil {
		http.Error(w, "server error", http.StatusInternalServerError)
		return
	}
	srv.ok(w, tk)
}

func (srv *tokenServer) authorize(opt *Option) []string {
	// do proper comparison to check for user's access
	// against the requested actions
	if opt.account == "foo" {
		return []string{"pull", "push"}
	}
	if opt.account == "bar" {
		return []string{"pull"}
	}
	// unauthorized, no permission is granted
	return []string{}
}

func (srv *tokenServer) run() error {
	addr := fmt.Sprintf(":%s", os.Getenv("PORT"))
	http.Handle("/auth", srv)
	return http.ListenAndServeTLS(addr, srv.crt, srv.key, nil)
}

func (srv *tokenServer) createTokenOption(r *http.Request) *Option {
	opt := &Option{}
	q := r.URL.Query()
	// log.Println(q)
	opt.service = q.Get("service")
	opt.account = q.Get("account")
	opt.issuer = "Sample Issuer" // issuer value must match the value configured via docker-compose

	parts := strings.Split(q.Get("scope"), ":")
	if len(parts) > 0 {
		opt.typ = parts[0] // repository
	}
	if len(parts) > 1 {
		opt.name = parts[1] // foo/repoName
	}
	if len(parts) > 2 {
		opt.actions = strings.Split(parts[2], ",") // requested actions
	}
	return opt
}

func (srv *tokenServer) ok(w http.ResponseWriter, i interface{}) {
	data, _ := json.Marshal(i)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write(data)
}

func loadCertAndKey(certFile, keyFile string) (libtrust.PublicKey, libtrust.PrivateKey, error) {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, nil, err
	}
	x509Cert, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return nil, nil, err
	}
	pk, err := libtrust.FromCryptoPublicKey(x509Cert.PublicKey)
	if err != nil {
		return nil, nil, err
	}
	prk, err := libtrust.FromCryptoPrivateKey(cert.PrivateKey)
	if err != nil {
		return nil, nil, err
	}
	return pk, prk, nil
}

func encodeBase64(b []byte) string {
	return strings.TrimRight(base64.URLEncoding.EncodeToString(b), "=")
}
