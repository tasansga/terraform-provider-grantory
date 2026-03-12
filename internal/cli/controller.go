package cli

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/spf13/cobra"

	k8scontroller "github.com/tasansga/terraform-provider-grantory/internal/k8s/controller"
	"github.com/tasansga/terraform-provider-grantory/internal/server"
)

const (
	flagMetricsBindAddress     = "metrics-bind-address"
	flagHealthProbeBindAddress = "health-probe-bind-address"
	flagLeaderElect            = "leader-elect"
	flagLeaderElectionID       = "leader-election-id"
)

func newControllerCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "controller",
		Short: "Run the Grantory Kubernetes controller",
		RunE: func(cmd *cobra.Command, _ []string) error {
			ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGINT, syscall.SIGTERM)
			defer stop()

			metricsAddr, _ := cmd.Flags().GetString(flagMetricsBindAddress)
			healthAddr, _ := cmd.Flags().GetString(flagHealthProbeBindAddress)
			leaderElect, _ := cmd.Flags().GetBool(flagLeaderElect)
			leaderElectionID, _ := cmd.Flags().GetString(flagLeaderElectionID)
			controllerCfg, err := resolveControllerConfig(cmd)
			if err != nil {
				return err
			}
			namespace, err := resolveControllerNamespace(cmd)
			if err != nil {
				return err
			}

			return k8scontroller.Start(ctx, k8scontroller.Options{
				MetricsBindAddress:     metricsAddr,
				HealthProbeBindAddress: healthAddr,
				LeaderElect:            leaderElect,
				LeaderElectionID:       leaderElectionID,
				GrantoryServerURL:      controllerCfg.serverURL,
				GrantoryToken:          controllerCfg.token,
				GrantoryUser:           controllerCfg.user,
				GrantoryPassword:       controllerCfg.password,
				GrantoryNamespace:      namespace,
			})
		},
	}

	cmd.Flags().String(flagMetricsBindAddress, ":8080", "metrics bind address")
	cmd.Flags().String(flagHealthProbeBindAddress, ":8081", "health probe bind address")
	cmd.Flags().Bool(flagLeaderElect, false, "enable leader election")
	cmd.Flags().String(flagLeaderElectionID, "grantory-controller", "leader election ID")

	return cmd
}

type controllerConfig struct {
	serverURL string
	token     string
	user      string
	password  string
}

func resolveControllerConfig(cmd *cobra.Command) (controllerConfig, error) {
	flags := cmd.Root().PersistentFlags()

	var rawServerURL string
	if flag := flags.Lookup(FlagServerURL); flag != nil && flag.Changed {
		rawServerURL = flag.Value.String()
	} else {
		rawServerURL = firstNonEmpty(os.Getenv(EnvGrantoryControllerServerURL), os.Getenv(EnvServerURL))
	}

	var rawToken string
	if flag := flags.Lookup(FlagToken); flag != nil && flag.Changed {
		rawToken = flag.Value.String()
	} else {
		rawToken = firstNonEmpty(os.Getenv(EnvGrantoryControllerToken), os.Getenv(EnvToken))
	}

	var rawUser string
	var rawPassword string
	if flag := flags.Lookup(FlagUser); flag != nil && flag.Changed {
		rawUser = flag.Value.String()
	} else {
		envUser, envPassword := controllerEnvUserPassword()
		rawUser = envUser
		rawPassword = envPassword
	}
	if flag := flags.Lookup(FlagPassword); flag != nil && flag.Changed {
		rawPassword = flag.Value.String()
	}

	serverURL := strings.TrimSpace(rawServerURL)
	token := strings.TrimSpace(rawToken)
	user := strings.TrimSpace(rawUser)
	password := strings.TrimSpace(rawPassword)

	if token != "" && (user != "" || password != "") {
		return controllerConfig{}, fmt.Errorf("token/Bearer auth cannot be combined with user/password")
	}
	if (user != "") != (password != "") {
		return controllerConfig{}, fmt.Errorf("both %s and %s must be provided together for basic auth", FlagUser, FlagPassword)
	}
	if serverURL == "" {
		return controllerConfig{}, fmt.Errorf("server URL is required for the controller")
	}

	return controllerConfig{
		serverURL: serverURL,
		token:     token,
		user:      user,
		password:  password,
	}, nil
}

func resolveControllerNamespace(cmd *cobra.Command) (string, error) {
	flagSet := cmd.Root().PersistentFlags()
	namespace, err := flagSet.GetString(FlagNamespace)
	if err != nil {
		return "", err
	}
	if namespace == "" {
		namespace = firstNonEmpty(os.Getenv(EnvGrantoryControllerNamespace), os.Getenv(EnvNamespace))
	}
	if namespace == "" {
		namespace = server.DefaultNamespace
	}
	if err := server.ValidateNamespaceName(namespace); err != nil {
		return "", err
	}
	return namespace, nil
}

func controllerEnvUserPassword() (string, string) {
	envUser := os.Getenv(EnvGrantoryControllerUser)
	envPassword := os.Getenv(EnvGrantoryControllerPassword)
	if envUser != "" && envPassword != "" {
		return envUser, envPassword
	}
	envUser = os.Getenv(EnvUser)
	envPassword = os.Getenv(EnvPassword)
	if envUser != "" && envPassword != "" {
		return envUser, envPassword
	}
	return "", ""
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}
