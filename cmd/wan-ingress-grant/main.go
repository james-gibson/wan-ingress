// Command wan-ingress-grant is the signing authority's issuer.
//
// It mints the capacity grant an ingress presents: a namespace, a ticket batch,
// a connection ceiling and an expiry, signed with Ed25519. The front verifies
// with the public key and cannot mint, which is the point — capacity is
// something the authority says, not something a front decides.
//
//	wan-ingress-grant -keygen
//	wan-ingress-grant -key <base64> -namespace session-42 -max-conns 8000 -ttl 1h
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/james-gibson/wan-ingress/internal/ingress"
)

func main() {
	keygen := flag.Bool("keygen", false, "generate a keypair and print both halves")
	key := flag.String("key", "", "authority private key, base64 (32-byte seed or 64-byte key)")
	namespace := flag.String("namespace", "", "namespace the holder may serve")
	batch := flag.Int("batch", 1024, "tickets the holder may hold")
	maxConns := flag.Int("max-conns", 8000, "connections the holder may admit")
	ttl := flag.Duration("ttl", 24*time.Hour, "how long the grant is valid")
	issuer := flag.String("issuer", "", "label for the authority (recorded, not trusted)")
	out := flag.String("out", "", "write the grant here instead of stdout")
	flag.Parse()

	if *keygen {
		pub, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			log.Fatal(err)
		}
		fmt.Printf("private %s\n", base64.RawURLEncoding.EncodeToString(priv))
		fmt.Printf("public  %s\n", base64.RawURLEncoding.EncodeToString(pub))
		return
	}
	if *key == "" {
		log.Fatal("-key is required (or -keygen to make one)")
	}
	if *namespace == "" {
		log.Fatal("-namespace is required")
	}
	if *batch <= 0 || *maxConns <= 0 || *ttl <= 0 {
		log.Fatal("batch, max-conns and ttl must be positive")
	}

	priv, err := privateKey(*key)
	if err != nil {
		log.Fatal(err)
	}
	grant := ingress.SignGrant(priv, ingress.Grant{
		Namespace: *namespace,
		Batch:     *batch,
		MaxConns:  *maxConns,
		Expires:   time.Now().Add(*ttl).Unix(),
		Issuer:    *issuer,
	})
	raw, err := json.MarshalIndent(grant, "", "  ")
	if err != nil {
		log.Fatal(err)
	}
	raw = append(raw, '\n')
	if *out == "" {
		_, _ = os.Stdout.Write(raw)
		return
	}
	if err := os.WriteFile(*out, raw, 0o644); err != nil { //nolint:gosec // a grant is public material
		log.Fatal(err)
	}
	log.Printf("grant written to %s", *out)
}

func privateKey(text string) (ed25519.PrivateKey, error) {
	raw, err := base64.RawURLEncoding.DecodeString(text)
	if err != nil {
		if raw, err = base64.StdEncoding.DecodeString(text); err != nil {
			return nil, fmt.Errorf("key is not base64: %w", err)
		}
	}
	switch len(raw) {
	case ed25519.SeedSize:
		return ed25519.NewKeyFromSeed(raw), nil
	case ed25519.PrivateKeySize:
		return ed25519.PrivateKey(raw), nil
	default:
		return nil, fmt.Errorf("key is %d bytes, want %d (seed) or %d (private key)",
			len(raw), ed25519.SeedSize, ed25519.PrivateKeySize)
	}
}
