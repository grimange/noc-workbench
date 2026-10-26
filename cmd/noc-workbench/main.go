package main

import (
	"context"
	"errors"
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
	if len(os.Args) > 1 {
		if len(os.Args) != 3 || os.Args[1] != "--ssh-lab-profile" {
			return errors.New("unsupported application arguments")
		}
		return app.RunSSHProbe(ctx, cfg, os.Args[2], logger)
	}
	return app.Run(ctx, cfg, logger)
}
