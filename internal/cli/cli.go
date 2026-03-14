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
	resourceTypeSchemas   resourceType = "schema-definitions"
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
		var store storage.Store
		if storage.IsPostgresDSN(cfg.Database) {
			pgStore, err := storage.NewPostgres(ctx, cfg.Database)
			if err != nil {
				return err
			}
			store = pgStore
		} else {
			if err := os.MkdirAll(cfg.Database, 0o755); err != nil {
				return fmt.Errorf("create sqlite directory: %w", err)
			}
			path := server.NamespaceDBPath(cfg.Database, namespace)
			sqliteStore, err := storage.New(ctx, path)
			if err != nil {
				return err
			}
			store = sqliteStore
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
		Short: "List hosts, requests, registers, grants, or schema definitions",
		Long: "List resources and return JSON arrays of objects.\n\n" +
			"Examples:\n" +
			"  grantory list hosts\n" +
			"  grantory list requests\n" +
			"  grantory list schema-definitions\n",
		Args: cobra.ExactArgs(1),
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
					return outputJSON(cmd, hosts)
				case resourceTypeRequests:
					requests, err := backend.ListRequests(ctx, nil)
					if err != nil {
						return err
					}
					return outputJSON(cmd, requests)
				case resourceTypeRegisters:
					registers, err := backend.ListRegisters(ctx, nil)
					if err != nil {
						return err
					}
					return outputJSON(cmd, registers)
				case resourceTypeGrants:
					grants, err := backend.ListGrants(ctx)
					if err != nil {
						return err
					}
					return outputJSON(cmd, grants)
				case resourceTypeSchemas:
					defs, err := backend.ListSchemaDefinitions(ctx)
					if err != nil {
						return err
					}
					return outputJSON(cmd, defs)
				default:
					return fmt.Errorf("unsupported resource type: %s", resType)
				}
			})
		},
	}
}

func newCreateCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "create <resource_type>",
		Short: "Create a request, register, grant, or schema definition",
		Long: "Create requests, registers, grants, or schema definitions using JSON files.\n\n" +
			"Examples:\n" +
			"  grantory create requests --host-id <host-id> --payload-file request.json\n" +
			"  grantory create registers --host-id <host-id> --payload-file register.json\n" +
			"  grantory create grants --request-id <request-id> --payload-file grant.json\n" +
			"  grantory create schema-definitions --schema-file schema.json --unique-key invoice.v1\n",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			resType, err := parseResourceType(args[0])
			if err != nil {
				return err
			}

			switch resType {
			case resourceTypeRequests:
				return createRequest(cmd)
			case resourceTypeRegisters:
				return createRegister(cmd)
			case resourceTypeGrants:
				return createGrant(cmd)
			case resourceTypeSchemas:
				return createSchemaDefinition(cmd)
			default:
				return fmt.Errorf("create does not support resource type: %s", resType)
			}
		},
	}

	cmd.Flags().String("host-id", "", "host identifier for the request")
	cmd.Flags().String("request-id", "", "request identifier for the grant")
	cmd.Flags().String("request-schema-id", "", "request schema definition identifier (requests only)")
	cmd.Flags().String("grant-schema-id", "", "grant schema definition identifier (requests only)")
	cmd.Flags().String("register-schema-id", "", "schema definition identifier (registers only)")
	cmd.Flags().String("unique-key", "", "unique key (requests/registers only)")
	cmd.Flags().String("payload-file", "", "path to a JSON file containing the payload")
	cmd.Flags().String("schema-file", "", "path to a JSON file containing a JSON schema (schema-definitions only)")
	cmd.Flags().String("labels", "", "JSON object that sets labels (requests/registers/schema-definitions)")
	cmd.Flags().String("labels-file", "", "path to a JSON file that sets labels (requests/registers/schema-definitions)")

	return cmd
}

func newInspectCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "inspect <resource_type> <id>",
		Short: "Show a single host, request, register, grant, or schema definition",
		Long: "Show a single resource as JSON.\n\n" +
			"For requests, the response also includes the applied grant ID and payload if present.\n\n" +
			"Examples:\n" +
			"  grantory inspect hosts <host-id>\n" +
			"  grantory inspect requests <request-id>\n" +
			"  grantory inspect requests <request-id> | jq '.grant_id, .grant_payload'\n",
		Args: cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			resType, err := parseResourceType(args[0])
			if err != nil {
				return err
			}
			id := args[1]

			return runWithBackend(cmd, func(ctx context.Context, backend cliBackend) error {
				if resType == resourceTypeRequests {
					response, err := fetchRequestInspectResponse(ctx, backend, id)
					if err != nil {
						return err
					}
					return outputJSON(cmd, response)
				}

				resource, err := fetchResource(ctx, backend, resType, id)
				if err != nil {
					return err
				}
				return outputJSON(cmd, resource)
			})
		},
	}
}

func createRequest(cmd *cobra.Command) error {
	hostID, err := cmd.Flags().GetString("host-id")
	if err != nil {
		return err
	}
	if strings.TrimSpace(hostID) == "" {
		return errors.New("--host-id is required for requests")
	}

	payloadFile, err := cmd.Flags().GetString("payload-file")
	if err != nil {
		return err
	}
	payload, err := loadJSONMapFromFile(payloadFile)
	if err != nil {
		return err
	}

	requestSchemaID, err := cmd.Flags().GetString("request-schema-id")
	if err != nil {
		return err
	}
	grantSchemaID, err := cmd.Flags().GetString("grant-schema-id")
	if err != nil {
		return err
	}
	uniqueKey, err := cmd.Flags().GetString("unique-key")
	if err != nil {
		return err
	}
	labelsFlag, err := cmd.Flags().GetString("labels")
	if err != nil {
		return err
	}
	labelsFile, err := cmd.Flags().GetString("labels-file")
	if err != nil {
		return err
	}
	if labelsFlag != "" && labelsFile != "" {
		return errors.New("only one of --labels or --labels-file may be provided")
	}

	var labels map[string]string
	if labelsFlag != "" || labelsFile != "" {
		labels, err = resolveLabels(cmd, labelsFlag, labelsFile)
		if err != nil {
			return err
		}
	}

	return runWithBackend(cmd, func(ctx context.Context, backend cliBackend) error {
		created, err := backend.CreateRequest(ctx, storage.Request{
			HostID:                    strings.TrimSpace(hostID),
			RequestSchemaDefinitionID: strings.TrimSpace(requestSchemaID),
			GrantSchemaDefinitionID:   strings.TrimSpace(grantSchemaID),
			UniqueKey:                 strings.TrimSpace(uniqueKey),
			Payload:                   payload,
			Labels:                    labels,
		})
		if err != nil {
			return err
		}
		return outputJSON(cmd, created)
	})
}

func createRegister(cmd *cobra.Command) error {
	hostID, err := cmd.Flags().GetString("host-id")
	if err != nil {
		return err
	}
	if strings.TrimSpace(hostID) == "" {
		return errors.New("--host-id is required for registers")
	}

	payloadFile, err := cmd.Flags().GetString("payload-file")
	if err != nil {
		return err
	}
	payload, err := loadJSONMapFromFile(payloadFile)
	if err != nil {
		return err
	}

	schemaID, err := cmd.Flags().GetString("register-schema-id")
	if err != nil {
		return err
	}
	uniqueKey, err := cmd.Flags().GetString("unique-key")
	if err != nil {
		return err
	}
	labelsFlag, err := cmd.Flags().GetString("labels")
	if err != nil {
		return err
	}
	labelsFile, err := cmd.Flags().GetString("labels-file")
	if err != nil {
		return err
	}
	if labelsFlag != "" && labelsFile != "" {
		return errors.New("only one of --labels or --labels-file may be provided")
	}

	var labels map[string]string
	if labelsFlag != "" || labelsFile != "" {
		labels, err = resolveLabels(cmd, labelsFlag, labelsFile)
		if err != nil {
			return err
		}
	}

	return runWithBackend(cmd, func(ctx context.Context, backend cliBackend) error {
		created, err := backend.CreateRegister(ctx, storage.Register{
			HostID:             strings.TrimSpace(hostID),
			SchemaDefinitionID: strings.TrimSpace(schemaID),
			UniqueKey:          strings.TrimSpace(uniqueKey),
			Payload:            payload,
			Labels:             labels,
		})
		if err != nil {
			return err
		}
		return outputJSON(cmd, created)
	})
}

func createGrant(cmd *cobra.Command) error {
	requestID, err := cmd.Flags().GetString("request-id")
	if err != nil {
		return err
	}
	if strings.TrimSpace(requestID) == "" {
		return errors.New("--request-id is required for grants")
	}

	payloadFile, err := cmd.Flags().GetString("payload-file")
	if err != nil {
		return err
	}
	payload, err := loadJSONMapFromFile(payloadFile)
	if err != nil {
		return err
	}

	return runWithBackend(cmd, func(ctx context.Context, backend cliBackend) error {
		created, err := backend.CreateGrant(ctx, storage.Grant{
			RequestID: strings.TrimSpace(requestID),
			Payload:   payload,
		})
		if err != nil {
			return err
		}
		return outputJSON(cmd, created)
	})
}

func createSchemaDefinition(cmd *cobra.Command) error {
	schemaFile, err := cmd.Flags().GetString("schema-file")
	if err != nil {
		return err
	}
	schemaValue, err := loadRawJSONFromFile(schemaFile)
	if err != nil {
		return err
	}
	uniqueKey, err := cmd.Flags().GetString("unique-key")
	if err != nil {
		return err
	}
	labelsFlag, err := cmd.Flags().GetString("labels")
	if err != nil {
		return err
	}
	labelsFile, err := cmd.Flags().GetString("labels-file")
	if err != nil {
		return err
	}
	if labelsFlag != "" && labelsFile != "" {
		return errors.New("only one of --labels or --labels-file may be provided")
	}

	var labels map[string]string
	if labelsFlag != "" || labelsFile != "" {
		labels, err = resolveLabels(cmd, labelsFlag, labelsFile)
		if err != nil {
			return err
		}
	}

	return runWithBackend(cmd, func(ctx context.Context, backend cliBackend) error {
		created, err := backend.CreateSchemaDefinition(ctx, storage.SchemaDefinition{
			UniqueKey: strings.TrimSpace(uniqueKey),
			Schema:    schemaValue,
			Labels:    labels,
		})
		if err != nil {
			return err
		}
		return outputJSON(cmd, created)
	})
}

func newDeleteCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "delete <resource_type> <id>",
		Short: "Delete a host, request, register, grant, or schema definition",
		Long: "Delete a single resource by ID.\n\n" +
			"Examples:\n" +
			"  grantory delete requests <request-id>\n",
		Args: cobra.ExactArgs(2),
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
				case resourceTypeSchemas:
					if err := backend.DeleteSchemaDefinition(ctx, id); err != nil {
						return err
					}
				default:
					return fmt.Errorf("unsupported resource type: %s", resType)
				}
				return outputJSON(cmd, map[string]string{"id": id, "resource": string(resType), "status": "deleted"})
			})
		},
	}
}

func newMutateCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "mutate <resource_type> <id>",
		Short: "Mutate host, request, register, or schema definition labels",
		Long: "Replace labels for a host, request, register, or schema definition using JSON.\n\n" +
			"Examples:\n" +
			"  grantory mutate hosts <host-id> --labels '{\"env\":\"prod\"}'\n" +
			"  grantory mutate requests <request-id> --labels-file labels.json\n" +
			"  grantory mutate schema-definitions <id> --labels '{\"family\":\"invoice\"}'\n",
		Args: cobra.ExactArgs(2),
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
				case resourceTypeSchemas:
					if err := backend.UpdateSchemaDefinitionLabels(ctx, id, labels); err != nil {
						return err
					}
				default:
					return fmt.Errorf("mutate does not support resource type: %s", resType)
				}

				updated, err := fetchResource(ctx, backend, resType, id)
				if err != nil {
					return err
				}

				return outputJSON(cmd, updated)
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
	case "schema-definition", "schema-definitions", "schema_definition", "schema_definitions":
		return resourceTypeSchemas, nil
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
	case resourceTypeSchemas:
		return backend.GetSchemaDefinition(ctx, id)
	default:
		return nil, fmt.Errorf("unsupported resource type: %s", resType)
	}
}

type requestInspectResponse struct {
	storage.Request
	GrantID      string `json:"grant_id,omitempty"`
	GrantPayload any    `json:"grant_payload,omitempty"`
}

func fetchRequestInspectResponse(ctx context.Context, backend cliBackend, id string) (requestInspectResponse, error) {
	switch b := backend.(type) {
	case *directBackend:
		req, err := b.store.GetRequest(ctx, id)
		if err != nil {
			return requestInspectResponse{}, err
		}
		resp := requestInspectResponse{Request: req}
		grant, found, err := b.store.GetGrantForRequest(ctx, req.ID)
		if err != nil {
			return resp, err
		}
		if found {
			resp.GrantID = grant.ID
			if grant.Payload != nil {
				resp.GrantPayload = grant.Payload
			}
		}
		return resp, nil
	case *apiBackend:
		apiResp, err := b.client.GetRequest(ctx, id)
		if err != nil {
			return requestInspectResponse{}, err
		}
		resp := requestInspectResponse{Request: requestToStorage(apiResp)}
		if apiResp.GrantID != "" {
			resp.GrantID = apiResp.GrantID
			if apiResp.Grant != nil {
				if payload, ok := apiResp.Grant["payload"]; ok {
					resp.GrantPayload = payload
				}
			}
		}
		return resp, nil
	default:
		req, err := backend.GetRequest(ctx, id)
		if err != nil {
			return requestInspectResponse{}, err
		}
		return requestInspectResponse{Request: req}, nil
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

func loadJSONMapFromFile(path string) (map[string]any, error) {
	if strings.TrimSpace(path) == "" {
		return nil, nil
	}
	if path == "-" {
		return nil, errors.New("payload must be provided via a file path, not stdin")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open payload file: %w", err)
	}
	data, err := io.ReadAll(file)
	if cerr := file.Close(); cerr != nil && err == nil {
		return nil, fmt.Errorf("close payload file: %w", cerr)
	}
	if err != nil {
		return nil, fmt.Errorf("read payload: %w", err)
	}
	if len(data) == 0 {
		return nil, errors.New("payload file is empty")
	}
	var payload map[string]any
	if err := json.Unmarshal(data, &payload); err != nil {
		return nil, fmt.Errorf("parse payload: %w", err)
	}
	return payload, nil
}

func loadRawJSONFromFile(path string) (json.RawMessage, error) {
	if strings.TrimSpace(path) == "" {
		return nil, errors.New("--schema-file is required for schema-definitions")
	}
	if path == "-" {
		return nil, errors.New("schema must be provided via a file path, not stdin")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open schema file: %w", err)
	}
	data, err := io.ReadAll(file)
	if cerr := file.Close(); cerr != nil && err == nil {
		return nil, fmt.Errorf("close schema file: %w", cerr)
	}
	if err != nil {
		return nil, fmt.Errorf("read schema: %w", err)
	}
	if len(data) == 0 {
		return nil, errors.New("schema file is empty")
	}
	if !json.Valid(data) {
		return nil, errors.New("schema file contains invalid JSON")
	}
	return json.RawMessage(data), nil
}

func outputJSON(cmd *cobra.Command, value any) error {
	return outputJSONTo(cmd.OutOrStdout(), value)
}

func outputJSONTo(out io.Writer, value any) error {
	encoder := json.NewEncoder(out)
	encoder.SetIndent("", "  ")
	return encoder.Encode(value)
}

func newNamespaceCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "namespace",
		Short: "Manage namespace databases",
		Long:  "Manage namespace databases (direct backend) or schemas (Postgres).\n",
	}
	cmd.AddCommand(newNamespaceDeleteCmd())
	return cmd
}

func newNamespaceDeleteCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "delete <namespace>",
		Short: "Remove a namespace database",
		Long: "Remove a namespace database (SQLite) or schema (Postgres).\n\n" +
			"Examples:\n" +
			"  grantory namespace delete staging\n",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			namespace := args[0]
			if err := server.ValidateNamespaceName(namespace); err != nil {
				return err
			}

			cfg, err := loadConfig(cmd)
			if err != nil {
				return err
			}

			if storage.IsPostgresDSN(cfg.Database) {
				if err := dropPostgresNamespace(cmd.Context(), cfg.Database, namespace); err != nil {
					return err
				}
				return outputJSON(cmd, map[string]any{
					"namespace": namespace,
					"database":  cfg.Database,
					"status":    "deleted",
				})
			}

			path := server.NamespaceDBPath(cfg.Database, namespace)
			if err := removeNamespaceFiles(path); err != nil {
				return err
			}

			return outputJSON(cmd, map[string]any{
				"namespace": namespace,
				"path":      path,
				"status":    "deleted",
			})
		},
	}
}

func dropPostgresNamespace(ctx context.Context, dsn, namespace string) error {
	store, err := storage.NewPostgres(ctx, dsn)
	if err != nil {
		return err
	}
	defer func() {
		_ = store.Close()
	}()

	stmt := fmt.Sprintf(`DROP SCHEMA IF EXISTS %s CASCADE`, quoteIdent(namespace))
	if _, err := store.DB().ExecContext(ctx, stmt); err != nil {
		return fmt.Errorf("drop namespace schema: %w", err)
	}
	return nil
}

func quoteIdent(value string) string {
	escaped := strings.ReplaceAll(value, `"`, `""`)
	return `"` + escaped + `"`
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
