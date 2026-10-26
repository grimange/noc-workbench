package app

import (
	"context"
	"errors"
	"log/slog"
	"os"

	"noc-workbench/internal/store/postgres"
	"noc-workbench/internal/transport/sshcli"
	"noc-workbench/internal/workspace"
)

// RunSSHProbe is an explicit, local-operator diagnostic, never a web handler.
// Both the opt-in environment and protected enrollment are mandatory. The
// policy restricts it to a literal loopback endpoint; it cannot collect from
// customer targets. NW-008 will supply general enrollment and grants.
func RunSSHProbe(ctx context.Context, cfg Config, path string, logger *slog.Logger) error {
	if os.Getenv("NOC_SSH_LAB") != "1" {
		return errors.New("SSH lab diagnostic is disabled")
	}
	if err := cfg.Validate(); err != nil {
		return err
	}
	enrollment, err := sshcli.ReadEnrollment(path)
	if err != nil {
		return err
	}
	db, err := postgres.Open(ctx, cfg.DatabaseURL)
	if err != nil {
		return errors.New("SSH lab inventory unavailable")
	}
	defer db.Close()
	executor, err := sshcli.New(sshcli.FileApproval{Path: path, Inventory: db, Policy: sshcli.LabPolicy{}})
	if err != nil {
		return err
	}
	result, err := executor.Execute(ctx, workspace.Principal{ID: workspace.OperatorID}, enrollment.Profile.Target, "lab.probe.v1")
	// No raw stderr, command output, paths, addresses or credential references.
	logger.Info("SSH lab attempt", "actor_id", result.ActorID, "asset_id", result.AssetID, "endpoint_id", result.EndpointID, "command_id", result.CommandID, "profile_id", result.ProfileID, "profile_version", result.ProfileVersion, "started_at", result.StartedAt, "ended_at", result.EndedAt, "duration_ms", result.Duration.Milliseconds(), "exit_code", result.ExitCode, "category", result.Category)
	if err != nil {
		return err
	}
	if string(result.Stdout) != "NOC_WORKBENCH_SSH_LAB_OK\n" {
		return errors.New("SSH lab command returned unexpected output")
	}
	return nil
}
