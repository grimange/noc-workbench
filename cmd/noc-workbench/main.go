package main

import (
	"context"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"noc-workbench/internal/app"
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stderr, nil))
	if err := execute(logger); err != nil {
		logger.Error("application stopped", "reason", err.Error())
		os.Exit(1)
	}
}

func execute(logger *slog.Logger) error {
	cfg, err := app.Load()
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return app.Run(ctx, cfg, logger)
}
