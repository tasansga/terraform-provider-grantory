package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/tasansga/terraform-provider-grantory/internal/config"
	"github.com/tasansga/terraform-provider-grantory/internal/server"
	"github.com/tasansga/terraform-provider-grantory/internal/storage"
)

type resourceType string

const (
	resourceTypeHosts     resourceType = "hosts"
	resourceTypeRequests  resourceType = "requests"
	resourceTypeGrants    resourceType = "grants"
	resourceTypeRegisters resourceType = "registers"
)

func loadConfig(cmd *cobra.Command) (config.Config, error) {
	return config.FromFlagSet(cmd.Root().PersistentFlags())
}

func runWithBackend(cmd *cobra.Command, action func(context.Context, cliBackend) error) error {
	cfg, err := loadConfig(cmd)
	if err != nil {
		return err
	}

	namespace, err := resolveNamespace(cmd)
	if err != nil {
		return err
	}

	backendCfg, err := resolveBackendConfig(cmd)
	if err != nil {
		return err
	}

	ctx := cmd.Context()
	switch backendCfg.mode {
	case backendModeDirect:
		if err := os.MkdirAll(cfg.DataDir, 0o755); err != nil {
			return fmt.Errorf("create data directory: %w", err)
		}
		path := server.NamespaceDBPath(cfg.DataDir, namespace)
		store, err := storage.New(ctx, path)
		if err != nil {
			return err
		}
		store.SetNamespace(namespace)
		defer func() {
			if err := store.Close(); err != nil {
				if _, ferr := fmt.Fprintf(cmd.ErrOrStderr(), "close store: %v\n", err); ferr != nil {
					_ = ferr
				}
			}
		}()

		if err := store.Migrate(ctx); err != nil {
			return err
		}

		return action(ctx, newDirectBackend(store))
	case backendModeAPI:
		backend, err := newAPIBackend(namespace, backendCfg.serverURL, backendCfg.token, backendCfg.user, backendCfg.password)
		if err != nil {
			return err
		}
		return action(ctx, backend)
	default:
		return fmt.Errorf("unsupported backend %q", backendCfg.mode)
	}
}

func newListCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "list <resource_type>",
		Short: "List hosts, requests, registers, or grants",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			resType, err := parseResourceType(args[0])
			if err != nil {
				return err
			}

			return runWithBackend(cmd, func(ctx context.Context, backend cliBackend) error {
				switch resType {
				case resourceTypeHosts:
					hosts, err := backend.ListHosts(ctx)
					if err != nil {
						return err
					}
					return outputJSON(hosts)
				case resourceTypeRequests:
					requests, err := backend.ListRequests(ctx)
					if err != nil {
						return err
					}
					return outputJSON(requests)
				case resourceTypeRegisters:
					registers, err := backend.ListRegisters(ctx)
					if err != nil {
						return err
					}
					return outputJSON(registers)
				case resourceTypeGrants:
					grants, err := backend.ListGrants(ctx)
					if err != nil {
						return err
					}
					return outputJSON(grants)
				default:
					return fmt.Errorf("unsupported resource type: %s", resType)
				}
			})
		},
	}
}

func newInspectCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "inspect <resource_type> <id>",
		Short: "Show a single host, request, register, or grant",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			resType, err := parseResourceType(args[0])
			if err != nil {
				return err
			}
			id := args[1]

			return runWithBackend(cmd, func(ctx context.Context, backend cliBackend) error {
				resource, err := fetchResource(ctx, backend, resType, id)
				if err != nil {
					return err
				}
				return outputJSON(resource)
			})
		},
	}
}

func newDeleteCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "delete <resource_type> <id>",
		Short: "Delete a host, request, register, or grant",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			resType, err := parseResourceType(args[0])
			if err != nil {
				return err
			}
			id := args[1]

			return runWithBackend(cmd, func(ctx context.Context, backend cliBackend) error {
				switch resType {
				case resourceTypeHosts:
					if err := backend.DeleteHost(ctx, id); err != nil {
						return err
					}
				case resourceTypeRequests:
					if err := backend.DeleteRequest(ctx, id); err != nil {
						return err
					}
				case resourceTypeRegisters:
					if err := backend.DeleteRegister(ctx, id); err != nil {
						return err
					}
				case resourceTypeGrants:
					if err := backend.DeleteGrant(ctx, id); err != nil {
						return err
					}
				default:
					return fmt.Errorf("unsupported resource type: %s", resType)
				}
				return outputJSON(map[string]string{"id": id, "resource": string(resType), "status": "deleted"})
			})
		},
	}
}

func newMutateCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "mutate <resource_type> <id>",
		Short: "Mutate host, request, or register labels",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			resType, err := parseResourceType(args[0])
			if err != nil {
				return err
			}
			id := args[1]

			labelsFlag, err := cmd.Flags().GetString("labels")
			if err != nil {
				return err
			}
			labelsFile, err := cmd.Flags().GetString("labels-file")
			if err != nil {
				return err
			}

			if labelsFlag == "" && labelsFile == "" {
				return errors.New("either --labels or --labels-file is required when mutating labels")
			}
			if labelsFlag != "" && labelsFile != "" {
				return errors.New("only one of --labels or --labels-file may be provided")
			}

			return runWithBackend(cmd, func(ctx context.Context, backend cliBackend) error {
				labels, err := resolveLabels(cmd, labelsFlag, labelsFile)
				if err != nil {
					return err
				}
				switch resType {
				case resourceTypeHosts:
					if err := backend.UpdateHostLabels(ctx, id, labels); err != nil {
						return err
					}
				case resourceTypeRequests:
					if err := backend.UpdateRequestLabels(ctx, id, labels); err != nil {
						return err
					}
				case resourceTypeRegisters:
					if err := backend.UpdateRegisterLabels(ctx, id, labels); err != nil {
						return err
					}
				default:
					return fmt.Errorf("mutate does not support resource type: %s", resType)
				}

				updated, err := fetchResource(ctx, backend, resType, id)
				if err != nil {
					return err
				}

				return outputJSON(updated)
			})
		},
	}

	cmd.Flags().String("labels", "", "JSON object that replaces labels")
	cmd.Flags().String("labels-file", "", "path to a JSON file (or - for STDIN) that replaces labels")

	return cmd
}

func parseResourceType(value string) (resourceType, error) {
	switch strings.ToLower(value) {
	case "host", "hosts":
		return resourceTypeHosts, nil
	case "request", "requests":
		return resourceTypeRequests, nil
	case "register", "registers":
		return resourceTypeRegisters, nil
	case "grant", "grants":
		return resourceTypeGrants, nil
	default:
		return "", fmt.Errorf("unknown resource type %q", value)
	}
}

func fetchResource(ctx context.Context, backend cliBackend, resType resourceType, id string) (any, error) {
	switch resType {
	case resourceTypeHosts:
		return backend.GetHost(ctx, id)
	case resourceTypeRequests:
		return backend.GetRequest(ctx, id)
	case resourceTypeRegisters:
		return backend.GetRegister(ctx, id)
	case resourceTypeGrants:
		return backend.GetGrant(ctx, id)
	default:
		return nil, fmt.Errorf("unsupported resource type: %s", resType)
	}
}

func parseLabels(raw string) (map[string]string, error) {
	if raw == "" {
		return nil, nil
	}

	var labels map[string]string
	if err := json.Unmarshal([]byte(raw), &labels); err != nil {
		return nil, fmt.Errorf("parse labels: %w", err)
	}
	return labels, nil
}

func resolveLabels(cmd *cobra.Command, labelsFlag, labelsFile string) (map[string]string, error) {
	if labelsFlag != "" {
		return parseLabels(labelsFlag)
	}
	if labelsFile != "" {
		return loadLabelsFromSource(cmd, labelsFile)
	}
	return nil, errors.New("either labels or labels-file must be provided")
}

func loadLabelsFromSource(cmd *cobra.Command, source string) (map[string]string, error) {
	var data []byte
	if source == "-" {
		var err error
		data, err = io.ReadAll(cmd.InOrStdin())
		if err != nil {
			return nil, fmt.Errorf("read labels: %w", err)
		}
	} else {
		file, err := os.Open(source)
		if err != nil {
			return nil, fmt.Errorf("open labels file: %w", err)
		}
		data, err = io.ReadAll(file)
		if cerr := file.Close(); cerr != nil {
			if err == nil {
				return nil, fmt.Errorf("close labels file: %w", cerr)
			}
		}
		if err != nil {
			return nil, fmt.Errorf("read labels: %w", err)
		}
	}
	if len(data) == 0 {
		return nil, errors.New("labels payload is empty")
	}
	return parseLabels(string(data))
}

func outputJSON(value any) error {
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	return encoder.Encode(value)
}

func newNamespaceCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "namespace",
		Short: "Manage namespace databases",
	}
	cmd.AddCommand(newNamespaceDeleteCmd())
	return cmd
}

func newNamespaceDeleteCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "delete <namespace>",
		Short: "Remove a namespace database",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			namespace := args[0]
			if err := server.ValidateNamespaceName(namespace); err != nil {
				return err
			}

			cfg, err := loadConfig(cmd)
			if err != nil {
				return err
			}

			path := server.NamespaceDBPath(cfg.DataDir, namespace)
			if err := removeNamespaceFiles(path); err != nil {
				return err
			}

			return outputJSON(map[string]any{
				"namespace": namespace,
				"path":      path,
				"status":    "deleted",
			})
		},
	}
}

func resolveNamespace(cmd *cobra.Command) (string, error) {
	flagSet := cmd.Root().PersistentFlags()
	namespace, err := flagSet.GetString(FlagNamespace)
	if err != nil {
		return "", err
	}
	if namespace == "" {
		namespace = os.Getenv(EnvNamespace)
	}
	if namespace == "" {
		namespace = server.DefaultNamespace
	}
	if err := server.ValidateNamespaceName(namespace); err != nil {
		return "", err
	}
	return namespace, nil
}

func removeNamespaceFiles(path string) error {
	suffixes := []string{"", "-wal", "-shm"}
	for _, suffix := range suffixes {
		name := path
		if suffix != "" {
			name = name + suffix
		}
		if err := os.Remove(name); err != nil {
			if errors.Is(err, os.ErrNotExist) {
				continue
			}
			return fmt.Errorf("remove %s: %w", name, err)
		}
	}
	return nil
}
