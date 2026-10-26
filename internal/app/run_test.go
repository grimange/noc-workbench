package app

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestServeShutdown(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	logger := slog.New(slog.NewJSONHandler(io.Discard, nil))
	go func() {
		done <- serve(ctx, listener, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusNoContent) }), logger)
	}()
	client := &http.Client{Timeout: time.Second}
	response, err := client.Get("http://" + listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusNoContent {
		t.Fatal(response.StatusCode)
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(6 * time.Second):
		t.Fatal("server did not stop within shutdown budget")
	}
	if response, err := client.Get("http://" + listener.Addr().String()); err == nil {
		response.Body.Close()
		t.Fatal("server still accepts requests after shutdown")
	}
}

func TestRunDatabaseUnavailableSanitized(t *testing.T) {
	configEnv(t)
	// Reserve then close a loopback port, without contacting another service.
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := listener.Addr().String()
	listener.Close()
	t.Setenv("NOC_DATABASE_URL", "postgres://synthetic:sensitive-marker@"+address+"/noc?sslmode=disable")
	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	cfg.StartupTimeout = time.Second
	start := time.Now()
	var logs bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&logs, nil))
	err = Run(context.Background(), cfg, logger)
	if err == nil || strings.Contains(err.Error(), "sensitive-marker") || strings.Contains(err.Error(), cfg.DatabaseURL) {
		t.Fatal("database failure missing or discloses secret")
	}
	// Match the entrypoint's structured error logging, including the propagated error.
	logger.Error("application stopped", "reason", err.Error())
	if strings.Contains(logs.String(), "sensitive-marker") || strings.Contains(logs.String(), cfg.DatabaseURL) {
		t.Fatal("structured startup failure logs disclose a database credential")
	}
	if time.Since(start) > 3*time.Second {
		t.Fatal("database startup ignored configured deadline")
	}
}
