// Command healthcheck is a tiny stdlib HTTP probe for distroless containers.
// It exists so a hardened image can carry a real Docker HEALTHCHECK without
// shipping curl, wget or a shell.
package main

import (
	"flag"
	"fmt"
	"net/http"
	"os"
	"time"
)

func main() {
	url := flag.String("url", "http://127.0.0.1:8443/healthz", "health endpoint")
	timeout := flag.Duration("timeout", 2*time.Second, "request timeout")
	flag.Parse()

	client := &http.Client{Timeout: *timeout}
	resp, err := client.Get(*url)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	statusErr := error(nil)
	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		statusErr = fmt.Errorf("health status %s", resp.Status)
	}
	_ = resp.Body.Close()
	if statusErr != nil {
		fmt.Fprintln(os.Stderr, statusErr)
		os.Exit(1)
	}
}
