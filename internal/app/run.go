package app

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"time"

	"noc-workbench/internal/collection"
	linux "noc-workbench/internal/collectors/linux"
	"noc-workbench/internal/connections"
	"noc-workbench/internal/store/postgres"
	"noc-workbench/internal/web"
)

// Run opens the local database, applies migrations and serves until cancellation.
// Driver errors are deliberately not wrapped into logs: they can include secrets.
func Run(ctx context.Context, cfg Config, logger *slog.Logger) error {
	if err := cfg.Validate(); err != nil {
		return err
	}
	if logger == nil {
		logger = slog.Default()
	}
	startup, cancel := context.WithTimeout(ctx, cfg.StartupTimeout)
	defer cancel()
	db, err := postgres.Open(startup, cfg.DatabaseURL)
	if err != nil {
		return errors.New("local database startup failed")
	}
	defer db.Close()
	if err := startup.Err(); err != nil {
		return errors.New("application startup cancelled")
	}
	listener, err := net.Listen("tcp", cfg.Listen)
	if err != nil {
		return errors.New("local HTTP listener unavailable")
	}
	defer listener.Close()
	enrollment, err := connections.New(db, db, connections.Catalog(cfg.SSHCredentialCatalog), connections.OperatorPolicy{})
	if err != nil {
		return errors.New("connection workflow initialization failed")
	}
	if err := db.RecoverCollections(startup); err != nil {
		return errors.New("collection recovery failed")
	}
	discovery := collection.NewService(enrollment, linux.Registry(), db)
	if cfg.CollectionTTL > 0 {
		discovery.TTLSeconds = cfg.CollectionTTL
	}
	if cfg.CollectionRunDays > 0 {
		discovery.RunDays = cfg.CollectionRunDays
	}
	if cfg.CollectionSampleDays > 0 {
		discovery.SampleDays = cfg.CollectionSampleDays
	}
	handler := web.New(db, web.Options{
		Enrollment: enrollment, Discovery: discovery, BaseURL: cfg.BaseURL, PasswordHash: cfg.PasswordHash,
		SessionTTL: cfg.SessionTTL, SecureCookie: cfg.SecureCookie,
	})
	logger.Info("application started", "listen", cfg.Listen)
	return serve(ctx, listener, handler, logger)
}

func serve(ctx context.Context, listener net.Listener, handler http.Handler, logger *slog.Logger) error {
	server := &http.Server{
		Handler: handler, ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout: 10 * time.Second, WriteTimeout: 15 * time.Second,
		IdleTimeout: 60 * time.Second, MaxHeaderBytes: 32 << 10,
		BaseContext: func(net.Listener) context.Context { return ctx },
	}
	finished := make(chan error, 1)
	go func() { finished <- server.Serve(listener) }()
	select {
	case err := <-finished:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return errors.New("HTTP server stopped unexpectedly")
	case <-ctx.Done():
		shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := server.Shutdown(shutdown); err != nil {
			_ = server.Close()
			return errors.New("HTTP shutdown deadline exceeded")
		}
		<-finished
		logger.Info("application stopped")
		return nil
	}
}
