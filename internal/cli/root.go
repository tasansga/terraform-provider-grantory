package cli

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"

	"github.com/tasansga/terraform-provider-grantory/internal/config"
	"github.com/tasansga/terraform-provider-grantory/internal/server"
	"github.com/tasansga/terraform-provider-grantory/internal/storage"
)

func NewRootCommand() *cobra.Command {
	root := &cobra.Command{
		Use:   "grantory",
		Short: "Grantory command-line interface",
		Long: "Manage Grantory resources or start the server with the 'serve' subcommand.\n\n" +
			"Examples:\n" +
			"  grantory serve\n" +
			"  grantory list hosts\n" +
			"  grantory inspect requests <request-id>\n",
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
		newControllerCmd(),
		newVersionCmd(),
		newNamespaceCmd(),
		newListCmd(),
		newCreateCmd(),
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
	cfg.ServerVersion = versionString()

	configureLogging(cfg)
	tlsStatus := "disabled"
	if server.IsTLSEnabled(cfg) {
		tlsStatus = "enabled"
	}
	fields := logrus.Fields{
		"http_bind":  cfg.BindAddr,
		"https_bind": cfg.TLSBind,
		"tls_cert":   cfg.TLSCert,
		"tls_key":    cfg.TLSKey,
		"tls":        tlsStatus,
		"version":    versionString(),
	}
	if storage.IsPostgresDSN(cfg.Database) {
		fields["database"] = redactPostgresDSN(cfg.Database)
	} else {
		absDataDir, err := filepath.Abs(cfg.Database)
		if err != nil {
			logrus.WithError(err).Warn("unable to resolve absolute sqlite directory")
			absDataDir = cfg.Database
		}
		fields["data_dir"] = absDataDir
	}
	logrus.WithFields(fields).Info("starting Grantory server")

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

func redactPostgresDSN(dsn string) string {
	parsed, err := url.Parse(dsn)
	if err != nil || parsed.Host == "" || parsed.Scheme == "" {
		return "postgres://redacted"
	}
	return fmt.Sprintf("%s://%s%s", parsed.Scheme, parsed.Host, parsed.Path)
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
		Long: "Start the HTTP API server that manages hosts, resource requests, and grants.\n\n" +
			"Examples:\n" +
			"  grantory serve\n",
		RunE: runServer,
	}
}

func newVersionCmd() *cobra.Command {
	return &cobra.Command{
		Use:     "version",
		Short:   "Print version information",
		Example: "  grantory version\n",
		RunE: func(cmd *cobra.Command, _ []string) error {
			_, err := fmt.Fprintln(cmd.OutOrStdout(), versionString())
			return err
		},
	}
}
