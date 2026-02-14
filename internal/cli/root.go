package cli

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"

	"github.com/tasansga/terraform-provider-grantory/internal/config"
	"github.com/tasansga/terraform-provider-grantory/internal/server"
)

func NewRootCommand() *cobra.Command {
	root := &cobra.Command{
		Use:   "grantory",
		Short: "Grantory command-line interface",
		Long:  "Manage Grantory resources or start the server with the 'serve' subcommand.",
		RunE: func(cmd *cobra.Command, args []string) error {
			return cmd.Help()
		},
	}
	root.Version = versionString()
	root.SetVersionTemplate("{{.Version}}\n")

	config.RegisterFlags(root.PersistentFlags())
	root.PersistentFlags().String(FlagBackend, string(backendModeDirect), fmt.Sprintf("backend to use (direct|api) (env: %s)", EnvBackend))
	root.PersistentFlags().String(FlagServerURL, "", "Grantory server URL (env: "+EnvServerURL+") used when --backend=api")
	root.PersistentFlags().String(FlagToken, "", "Bearer token for API requests (env: "+EnvToken+")")
	root.PersistentFlags().String(FlagUser, "", "Username for basic auth (env: "+EnvUser+")")
	root.PersistentFlags().String(FlagPassword, "", "Password for basic auth (env: "+EnvPassword+")")
	root.PersistentFlags().String(FlagNamespace, "", "namespace to target for CLI commands (env: "+EnvNamespace+")")
	root.PersistentFlags().SortFlags = false
	root.SilenceUsage = true

	root.AddCommand(
		newServeCmd(),
		newVersionCmd(),
		newNamespaceCmd(),
		newListCmd(),
		newInspectCmd(),
		newDeleteCmd(),
		newMutateCmd(),
	)

	return root
}

func runServer(cmd *cobra.Command, _ []string) error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	cfg, err := loadConfig(cmd)
	if err != nil {
		return err
	}

	absDataDir, err := filepath.Abs(cfg.DataDir)
	if err != nil {
		logrus.WithError(err).Warn("unable to resolve absolute data directory")
		absDataDir = cfg.DataDir
	}

	configureLogging(cfg)
	tlsStatus := "disabled"
	if server.IsTLSEnabled(cfg) {
		tlsStatus = "enabled"
	}
	logrus.WithFields(logrus.Fields{
		"data_dir": absDataDir,
		"http_bind":  cfg.BindAddr,
		"https_bind": cfg.TLSBind,
		"tls_cert": cfg.TLSCert,
		"tls_key":  cfg.TLSKey,
		"tls":      tlsStatus,
		"version":  versionString(),
	}).Info("starting Grantory server")

	srv, err := server.New(ctx, cfg)
	if err != nil {
		return err
	}
	defer func() {
		if err := srv.Close(); err != nil {
			logrus.WithError(err).Warn("close server")
		}
	}()

	err = srv.Serve(ctx)
	logrus.Info("stopping Grantory server")
	return err
}

func configureLogging(cfg config.Config) {
	logrus.SetOutput(os.Stdout)
	logrus.SetLevel(cfg.LogLevel)
	logrus.SetFormatter(&logrus.TextFormatter{
		FullTimestamp: true,
	})
}

func newServeCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "serve",
		Short: "Start the Grantory server",
		Long:  "Start the HTTP API server that manages hosts, resource requests, and grants.",
		RunE:  runServer,
	}
}

func newVersionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print version information",
		RunE: func(cmd *cobra.Command, _ []string) error {
			_, err := fmt.Fprintln(cmd.OutOrStdout(), versionString())
			return err
		},
	}
}
