// Command wan-ingress is a single static binary: a thin WAN-facing front that
// resolves arbitrary inbound names by agreement and forwards them only through
// a signed border. See internal/ingress/README.md and
// features/wan-ingress.feature.
//
//	wan-ingress -config=wan-ingress.json -addr=:8443
//
// SIGHUP reloads the config in place (a rejected config keeps the last good
// one). SIGTERM/SIGINT drain the listener and give up the registry name.
package main

import (
	"context"
	"errors"
	"flag"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/james-gibson/wan-ingress/internal/ingress"
)

const registryName = "wan-ingress"

// Flag values are package-level so applyFlags can tell an explicit override
// from a default: a config file must not be overwritten by an unset flag.
var (
	addr       = flag.String("addr", "127.0.0.1:8443", "bind address (0.0.0.0 is a bind, never a destination)")
	agreements = flag.String("agreements", "", "path to the JSON file of agreed mappings")
	token      = flag.String("token", "", "bearer token required for WAN admission")
	borderKey  = flag.String("border-key", "", "HMAC key for the signed border envelope")
	registry   = flag.String("smoke-alarm", "", "smoke-alarm registry URL to register by name")
	tlsCert    = flag.String("tls-cert", "", "PEM certificate for TLS termination")
	tlsKey     = flag.String("tls-key", "", "PEM private key for TLS termination")
	plaintext  = flag.Bool("allow-plaintext-wan", false, "bind publicly without TLS; TLS must be terminated in front")
	node       = flag.String("node", "", "this ingress's name in a route path (required in a sub-cluster)")
	peers      = flag.String("peers", "", "comma-separated IPs/CIDRs of ingress peers whose route path is believed")
	terminator = flag.String("terminator", "", "comma-separated IPs/CIDRs of the TLS terminator/LB in front")
	maxConns   = flag.Int("max-conns", 0, "hard cap on accepted connections (0 = unbounded)")
)

func main() {
	configPath := flag.String("config", "", "path to the JSON config (flags override its fields)")
	heartbeat := flag.Duration("heartbeat", ingress.HeartbeatInterval, "registry renewal interval")
	checkConfig := flag.Bool("check-config", false, "validate the config and exit without listening")
	flag.Parse()

	cfg, err := resolveConfig(*configPath)
	if err != nil {
		log.Fatalf("config: %v", err)
	}
	applyFlags(&cfg)
	if checkErr := ingress.CheckDeployable(cfg); checkErr != nil {
		log.Fatalf("refusing to start: %v", checkErr)
	}
	if cfg.MaxConns == 0 {
		log.Printf("warning: max_conns is unset; the connection count is bounded only by the host (docs/placement.md)")
	}
	if *checkConfig {
		log.Printf("config ok: addr=%s tls=%t agreements=%q max_conns=%d", cfg.Addr, cfg.TLSCert != "", cfg.Agreements, cfg.MaxConns)
		return
	}
	log.Printf("config loaded: agreements=%q ready=%t", cfg.Agreements, cfg.Token != "" && cfg.BorderKey != "")

	observer := ingress.NewObserver()
	server, err := ingress.NewServer(cfg, observer)
	if err != nil {
		log.Fatalf("load policy: %v", err)
	}
	runtime := &ingress.Runtime{}
	runtime.Swap(server)

	listener, err := net.Listen("tcp", cfg.Addr)
	if err != nil {
		log.Fatalf("listen %s: %v", cfg.Addr, err)
	}
	// The cap is applied to the listener, not the handler: unbounded connections
	// cost memory before a request is ever parsed.
	listener = ingress.NewLimitListener(listener, cfg.MaxConns)

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	// Register only once the listener is up: a name is a claim that something is
	// reachable, and the registry probes the endpoint it is given.
	if cfg.SmokeAlarm != "" {
		endpoint := endpointURL(cfg.TLSCert != "", listener.Addr().String())
		status, body, err := ingress.Register(ctx, cfg.SmokeAlarm, registryName, endpoint)
		if err != nil {
			log.Printf("smoke-alarm registration failed: %v", err)
		} else {
			log.Printf("registered name=%s endpoint=%s status=%d body=%s", registryName, endpoint, status, strings.TrimSpace(string(body)))
		}
		errs := ingress.KeepRegistered(ctx, cfg.SmokeAlarm, registryName, endpoint, *heartbeat)
		go func() {
			for err := range errs {
				log.Printf("registry heartbeat failed (will retry): %v", err)
			}
		}()
		defer func() {
			downCtx, stop := context.WithTimeout(context.Background(), 2*time.Second)
			defer stop()
			if err := ingress.Deregister(downCtx, cfg.SmokeAlarm, registryName); err != nil {
				log.Printf("deregister: %v", err)
			}
		}()
	}

	// SIGHUP swaps policy off to the side. An invalid file changes nothing.
	hup := make(chan os.Signal, 1)
	signal.Notify(hup, syscall.SIGHUP)
	defer signal.Stop(hup)
	go func() {
		for range hup {
			next, err := resolveConfig(*configPath)
			if err == nil {
				applyFlags(&next)
			}
			if err != nil {
				log.Printf("reload rejected, keeping last good config: %v", err)
				continue
			}
			if checkErr := ingress.CheckDeployable(next); checkErr != nil {
				log.Printf("reload rejected, keeping last good config: %v", checkErr)
				continue
			}
			srv, err := ingress.NewServer(next, observer)
			if err != nil {
				log.Printf("reload rejected, keeping last good policy: %v", err)
				continue
			}
			runtime.Swap(srv)
			log.Printf("reloaded config: agreements=%q ready=%t", next.Agreements, next.Token != "" && next.BorderKey != "")
		}
	}()

	httpServer := &http.Server{
		Handler:           runtime,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       60 * time.Second,
	}
	go func() {
		<-ctx.Done()
		shutdownCtx, stop := context.WithTimeout(context.Background(), 5*time.Second)
		defer stop()
		_ = httpServer.Shutdown(shutdownCtx)
	}()

	// A config reload may not rebind: the listener is the deployment, the
	// policy is the swap. Say so instead of silently ignoring a changed addr.
	log.Printf("wan-ingress listening on %s tls=%t plaintext_wan=%t max_conns=%d", listener.Addr(), cfg.TLSCert != "", cfg.AllowPlaintextWAN, cfg.MaxConns)
	var serveErr error
	if cfg.TLSCert != "" {
		serveErr = httpServer.ServeTLS(listener, cfg.TLSCert, cfg.TLSKey)
	} else {
		serveErr = httpServer.Serve(listener)
	}
	if serveErr != nil && !errors.Is(serveErr, http.ErrServerClosed) {
		log.Fatalf("serve: %v", serveErr) //nolint:gocritic // exiting; the deferred cleanups are best-effort
	}
}

// resolveConfig reads the file first; flags that were explicitly set win.
func resolveConfig(path string) (ingress.Config, error) {
	cfg, err := ingress.LoadConfigFile(path)
	if err != nil {
		return cfg, err
	}
	if cfg.Addr == "" {
		cfg.Addr = "127.0.0.1:8443"
	}
	return cfg, nil
}

func applyFlags(cfg *ingress.Config) {
	flag.Visit(func(f *flag.Flag) {
		switch f.Name {
		case "addr":
			cfg.Addr = *addr
		case "agreements":
			cfg.Agreements = *agreements
		case "token":
			cfg.Token = *token
		case "border-key":
			cfg.BorderKey = *borderKey
		case "smoke-alarm":
			cfg.SmokeAlarm = *registry
		case "tls-cert":
			cfg.TLSCert = *tlsCert
		case "tls-key":
			cfg.TLSKey = *tlsKey
		case "allow-plaintext-wan":
			cfg.AllowPlaintextWAN = *plaintext
		case "node":
			cfg.Node = *node
		case "peers":
			cfg.Peers = splitList(*peers)
		case "terminator":
			cfg.Terminator = splitList(*terminator)
		case "max-conns":
			cfg.MaxConns = *maxConns
		}
	})
}

// splitList reads a comma-separated flag into a slice, treating empty as none.
func splitList(value string) []string {
	var out []string
	for _, part := range strings.Split(value, ",") {
		if part = strings.TrimSpace(part); part != "" {
			out = append(out, part)
		}
	}
	return out
}

// endpointURL turns a listener address into the URL a dependent dials. A
// wildcard bind is a bind address, never a destination.
func endpointURL(tls bool, addr string) string {
	scheme := "http://"
	if tls {
		scheme = "https://"
	}
	return scheme + endpointHost(addr)
}

// endpointHost turns a listener address into a URL host.
func endpointHost(addr string) string {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return addr
	}
	if host == "" || host == "0.0.0.0" || host == "::" || host == "[::]" {
		host = "127.0.0.1"
	}
	return net.JoinHostPort(host, port)
}
