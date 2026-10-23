package controller

import (
	"context"
	"fmt"

	"k8s.io/apimachinery/pkg/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"

	"github.com/bombsimon/logrusr/v4"
	"github.com/go-logr/logr"
	"github.com/sirupsen/logrus"

	apiclient "github.com/tasansga/terraform-provider-grantory/api/client"
	"github.com/tasansga/terraform-provider-grantory/internal/k8s/api/v1alpha1"
)

// SetupLogger initializes controller-runtime's root logger using logrus and returns the configured logr.Logger.
// If logger is nil, logrus.StandardLogger() is used.
func SetupLogger(logger logrus.FieldLogger) logr.Logger {
	if isNilLogger(logger) {
		logger = logrus.StandardLogger()
	}
	l := logrusr.New(logger)
	ctrl.SetLogger(l)
	return l
}

func isNilLogger(l logrus.FieldLogger) bool {
	if l == nil {
		return true
	}
	switch v := l.(type) {
	case *logrus.Logger:
		return v == nil
	case *logrus.Entry:
		return v == nil
	default:
		return false
	}
}

type Options struct {
	// Logger is the Logrus logger to use for controller-runtime and reconciler logging.
	// If nil, logrus.StandardLogger() is used.
	Logger                  logrus.FieldLogger
	MetricsBindAddress      string
	HealthProbeBindAddress  string
	LeaderElect             bool
	LeaderElectionID        string
	GrantoryServerURL       string
	GrantoryToken           string
	GrantoryUser            string
	GrantoryPassword        string
	GrantoryNamespace       string
	AutoCreateHost          bool
	AutoHostName            string
	AutoHostSecret          string
	AutoHostSecretNamespace string
}

func Start(ctx context.Context, opts Options) error {
	logrLogger := SetupLogger(opts.Logger)

	scheme := runtime.NewScheme()
	if err := clientgoscheme.AddToScheme(scheme); err != nil {
		return fmt.Errorf("add core scheme: %w", err)
	}
	if err := v1alpha1.AddToScheme(scheme); err != nil {
		return fmt.Errorf("add grantory scheme: %w", err)
	}

	grantoryClient, err := apiclient.New(apiclient.Options{
		BaseURL:   opts.GrantoryServerURL,
		Token:     opts.GrantoryToken,
		User:      opts.GrantoryUser,
		Password:  opts.GrantoryPassword,
		Namespace: opts.GrantoryNamespace,
	})
	if err != nil {
		return fmt.Errorf("create grantory client: %w", err)
	}

	manager, err := ctrl.NewManager(ctrl.GetConfigOrDie(), ctrl.Options{
		Scheme:                 scheme,
		Logger:                 logrLogger,
		Metrics:                metricsserver.Options{BindAddress: opts.MetricsBindAddress},
		HealthProbeBindAddress: opts.HealthProbeBindAddress,
		LeaderElection:         opts.LeaderElect,
		LeaderElectionID:       opts.LeaderElectionID,
	})
	if err != nil {
		return fmt.Errorf("create manager: %w", err)
	}

	if err := manager.AddHealthzCheck("healthz", healthz.Ping); err != nil {
		return fmt.Errorf("add health check: %w", err)
	}
	if err := manager.AddReadyzCheck("readyz", healthz.Ping); err != nil {
		return fmt.Errorf("add ready check: %w", err)
	}

	var defaultHostProvider DefaultHostProvider
	if opts.AutoCreateHost {
		bootstrapper := NewClusterHostBootstrapper(manager.GetAPIReader(), manager.GetClient(), grantoryClient, ClusterHostOptions{
			HostName:        opts.AutoHostName,
			SecretName:      opts.AutoHostSecret,
			SecretNamespace: opts.AutoHostSecretNamespace,
		})
		if err := manager.Add(bootstrapper); err != nil {
			return fmt.Errorf("add cluster host bootstrapper: %w", err)
		}
		defaultHostProvider = bootstrapper
	}

	recorder := manager.GetEventRecorder("grantory-controller")
	if err := (&GrantoryHostReconciler{
		Client:            manager.GetClient(),
		Scheme:            manager.GetScheme(),
		Recorder:          recorder,
		GrantoryClient:    grantoryClient,
		GrantoryNamespace: opts.GrantoryNamespace,
	}).SetupWithManager(manager); err != nil {
		return fmt.Errorf("setup host controller: %w", err)
	}
	if err := (&GrantoryRequestReconciler{
		Client:              manager.GetClient(),
		Scheme:              manager.GetScheme(),
		Recorder:            recorder,
		GrantoryClient:      grantoryClient,
		GrantoryNamespace:   opts.GrantoryNamespace,
		DefaultHostProvider: defaultHostProvider,
	}).SetupWithManager(manager); err != nil {
		return fmt.Errorf("setup request controller: %w", err)
	}
	if err := (&GrantoryRegisterReconciler{
		Client:              manager.GetClient(),
		Scheme:              manager.GetScheme(),
		Recorder:            recorder,
		GrantoryClient:      grantoryClient,
		GrantoryNamespace:   opts.GrantoryNamespace,
		DefaultHostProvider: defaultHostProvider,
	}).SetupWithManager(manager); err != nil {
		return fmt.Errorf("setup register controller: %w", err)
	}

	return manager.Start(ctx)
}
