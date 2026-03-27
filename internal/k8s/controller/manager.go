package controller

import (
	"context"
	"fmt"

	"k8s.io/apimachinery/pkg/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"

	apiclient "github.com/tasansga/terraform-provider-grantory/api/client"
	"github.com/tasansga/terraform-provider-grantory/internal/k8s/api/v1alpha1"
)

type Options struct {
	MetricsBindAddress     string
	HealthProbeBindAddress string
	LeaderElect            bool
	LeaderElectionID       string
	GrantoryServerURL      string
	GrantoryToken          string
	GrantoryUser           string
	GrantoryPassword       string
	GrantoryNamespace      string
}

func Start(ctx context.Context, opts Options) error {
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

	recorder := manager.GetEventRecorderFor("grantory-controller")
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
		Client:            manager.GetClient(),
		Scheme:            manager.GetScheme(),
		Recorder:          recorder,
		GrantoryClient:    grantoryClient,
		GrantoryNamespace: opts.GrantoryNamespace,
	}).SetupWithManager(manager); err != nil {
		return fmt.Errorf("setup request controller: %w", err)
	}
	if err := (&GrantoryRegisterReconciler{
		Client:            manager.GetClient(),
		Scheme:            manager.GetScheme(),
		Recorder:          recorder,
		GrantoryClient:    grantoryClient,
		GrantoryNamespace: opts.GrantoryNamespace,
	}).SetupWithManager(manager); err != nil {
		return fmt.Errorf("setup register controller: %w", err)
	}

	return manager.Start(ctx)
}
