# Grantory

Grantory implements loose coupling between Terraform/OpenTofu pipelines to decouple producers, consumers, and grantors of runtime configuration. It's a small "control plane" for runtime registrations and requests. It replaces ad‑hoc file/variable wiring and lets workloads publish what they need while other components aggregate and act on those needs.

Producers register or request data into Grantory, consumers read registers or requests, and grantors issue grants.

Links:
- [Homepage](https://github.com/tasansga/terraform-provider-grantory)
- [OpenTofu registry](https://search.opentofu.org/provider/tasansga/grantory/latest)
- [terraform registry](https://registry.terraform.io/providers/tasansga/grantory/latest)
- [Go API client docs (pkg.go.dev)](https://pkg.go.dev/github.com/tasansga/terraform-provider-grantory/api/client)
- [Go embedded service docs (pkg.go.dev)](https://pkg.go.dev/github.com/tasansga/terraform-provider-grantory/api/service)
- [Go embedded server docs (pkg.go.dev)](https://pkg.go.dev/github.com/tasansga/terraform-provider-grantory/api/server)

## Concepts

- Producer – a pipeline or workload that publishes requests or registers.
- Consumer – a pipeline or workload that reads requests/registers to configure downstream systems.
- Grantor – a pipeline or workload that reviews requests and issues grants.
- Host – a remote node that registers labels with Grantory and becomes a reference (or owner) of requests/registers.
- Request – a workload or permission request emitted by a host.
- Grant – the workflow decision for a request. Grants reference a request and can carry operator-provided data. The database enforces that every grant belongs to exactly one request and that each request can have at most one grant.
- Register – a record that stores arbitrary data/labels for a host without expecting a grant.

## Core Patterns

### 1) Register → Aggregate → Consume

Producers register their data into Grantory (resource `grantory_register`). Consumers aggregate all registers (data sources `grantory_registers` + `grantory_register`).

### 2) Request → Grant → Use

Producers request something they need (resource `grantory_request`). Grantors (resource `grantory_grant`) issue grants and reply with information ("you have been granted access to `$this` database, secret is in `$path`). Producers receive this information and adapt their config accordingly.

## Terraform/OpenTofu workflow

Grantory is designed for multi-pipeline automation: one Terraform/OpenTofu pipeline declares a `grantory_request` (the "producer"), another pipeline or automation run inspects those requests and creates matching `grantory_grant` resources (the "grantor")

This allows pipelines with requests to act on them (e.g., to rotate secrets or provision proxies).

1. Request pipeline – this is typically a terraform or OpenTofu pipeline/module that creates a request describing the desired access, user creation, proxy, or other change. The request includes specific payload data (e.g., target user info or application metadata) and labels for filtering. When you only need to publish metadata without requesting a pipeline action, use the register instead.
2. Grant handler – watches for requests, filtered by label. It approves them by creating grant resources with additional payload like connection strings or service endpoints. This typically runs as cron job or another Terraform/OpenTofu pipeline.


### Provider configuration

```hcl
terraform {
  required_providers {
    grantory = {
      source  = "tasansga/grantory"
    }
  }
}

provider "grantory" {
  server = "http://localhost:8080"
}
```

HTTPS endpoint:

```hcl
provider "grantory" {
  server = "https://grantory.example.internal"
}
```

API auth (when enforced by your proxy/gateway):

```hcl
provider "grantory" {
  server = "https://grantory.example.internal"
  token  = var.grantory_token
}
```

SSH transport mode (no external tunnel command required):

```hcl
provider "grantory" {
  ssh_address          = "grantory.internal:22"
  ssh_user             = "grantory"
  ssh_private_key_path = pathexpand("~/.ssh/id_ed25519")
  ssh_known_hosts_path = pathexpand("~/.ssh/known_hosts")
  ssh_socket_path      = "/run/grantory/server.sock"
}
```

With bastion/jump host:

```hcl
provider "grantory" {
  ssh_address                  = "grantory.internal:22"
  ssh_user                     = "grantory"
  ssh_private_key_path         = pathexpand("~/.ssh/id_ed25519")
  ssh_known_hosts_path         = pathexpand("~/.ssh/known_hosts")
  ssh_socket_path              = "/run/grantory/server.sock"
  ssh_bastion_address          = "bastion.internal:22"
  ssh_bastion_user             = "ops"
  ssh_bastion_private_key_path = pathexpand("~/.ssh/id_ed25519_ops")
}
```

`server` and SSH transport settings are mutually exclusive. Configure one mode only.

SSH agent auth (useful for passphrase-protected keys):

```hcl
provider "grantory" {
  ssh_address           = "grantory.internal:22"
  ssh_user              = "grantory"
  ssh_use_agent         = true
  ssh_agent_socket_path = "/run/user/1000/ssh-agent.socket" # optional; defaults to SSH_AUTH_SOCK
  ssh_known_hosts_path  = pathexpand("~/.ssh/known_hosts")
  ssh_socket_path       = "/run/grantory/server.sock"
}
```

## Kubernetes workflow

**EXPERIMENTAL FEATURE**

Grantory can also be driven from Kubernetes using CRDs plus the built-in controller. App teams declare `GrantoryRequest` / `GrantoryRegister` custom resources, and the controller syncs them to a Grantory server instance. Grant handlers still run outside the cluster (or in-cluster) and issue grants via the API.

The CRDs live in `k8s/crds/` and the controller runs via `grantory controller`. It uses the same server configuration flags as the CLI and also supports `GRANTORY_CONTROLLER_*` env vars for server URL and credentials.
An example controller deployment (RBAC + Deployment) lives in `k8s/controller.yaml`.

## Running the server

Grantory runs as an HTTP server and can optionally expose the same API via a Unix domain socket. Configure the database (sqlite directory path or Postgres DSN), HTTP/HTTPS bind addresses, optional Unix socket listener, TLS certificates, and log level via flags or matching environment variables (`DATABASE`, `HTTP_BIND`, `HTTPS_BIND`, `UNIX_SOCKET`, `UNIX_SOCKET_MODE`, `TLS_CERT`, `TLS_KEY`, `LOG_LEVEL`). TLS is only activated if `TLS_CERT` and `TLS_KEY` are set. Set `HTTP_BIND=off` to disable the HTTP listener.

```bash
grantory --database ./data --http-bind 127.0.0.1:8080
```

Defaults: `HTTP_BIND=0.0.0.0:8080`, `HTTPS_BIND=0.0.0.0:8443`, `UNIX_SOCKET=""` (disabled), `UNIX_SOCKET_MODE=0660`.

When TLS is enabled, the server listens on both HTTP and HTTPS using those addresses. `HTTPS_BIND` is only evaluated when `TLS_CERT` and `TLS_KEY` are set.

```bash
grantory --http-bind 127.0.0.1:8080 --https-bind 127.0.0.1:8443 --tls-cert ./cert.pem --tls-key ./key.pem
```

To enable a Unix socket listener, set `--unix-socket` (or `UNIX_SOCKET`). This is opt-in and can run alongside HTTP/HTTPS listeners.

```bash
grantory --unix-socket /run/grantory/server.sock --unix-socket-mode 0660
```

Unix socket only mode:

```bash
grantory --http-bind off --https-bind off --unix-socket /run/grantory/server.sock
```

## Docker image

The Grantory server image is published to Docker Hub as [tasansga/grantory](https://hub.docker.com/r/tasansga/grantory).

```bash
docker run --rm -p 8080:8080 -v "$PWD/data:/data" tasansga/grantory:latest
```

Set `DATABASE`, `HTTP_BIND`, `HTTPS_BIND`, `UNIX_SOCKET`, `UNIX_SOCKET_MODE`, `TLS_CERT`, `TLS_KEY`, and `LOG_LEVEL` as needed to customize server behavior. The image starts as root, fixes ownership of the sqlite directory when `DATABASE` is a path, then drops privileges to the `grantory` user. If you run the container rootless, ensure the mounted sqlite directory is writable by that user.

## CLI

While Grantory is a terraform-focused tool, there's also a CLI for administrative purposes. The CLI can talk to SQLite directly (`--backend direct`, the default) or route every operation through the HTTP API (`--backend api`). Check `grantory --help` for details.

## Go API client library

This repository exposes a public Go client package for the Grantory HTTP API:

```go
import "github.com/tasansga/terraform-provider-grantory/api/client"
```

Minimal setup:

```go
c, err := client.New(client.Options{
  BaseURL: "https://grantory.example.internal",
})
```

Authentication is optional in Grantory itself. Set `Token` (Bearer) or `User` + `Password` only when your reverse proxy or gateway enforces it.

For embedded/in-process usage (function calls, no HTTP routing), use:

```go
import "github.com/tasansga/terraform-provider-grantory/api/service"
```

In-memory SQLite example:

```go
ctx := context.Background()

store, err := service.NewSQLiteStore(ctx, ":memory:")
if err != nil {
  panic(err)
}

svc := service.New(store)
host, err := svc.CreateHost(ctx, service.HostCreatePayload{
  UniqueKey: "app-01",
  Labels:    map[string]string{"env": "dev"},
})
if err != nil {
  panic(err)
}

fmt.Println(host.ID)
```

For embedded HTTP server usage (listeners + routes), use:

```go
cfg := server.DefaultConfig()
cfg.Database = "./data"
cfg.BindAddr = "127.0.0.1:8080"
cfg.TLSBind = "off"

srv, err := server.New(context.Background(), cfg)
if err != nil {
  panic(err)
}
defer srv.Close()

if err := srv.Serve(context.Background()); err != nil {
  panic(err)
}
```


## Authentication and namespaces

Grantory supports multi-tenancy.

In this setup, when the CLI or Terraform/OpenTofu provider talks to the HTTP API directly, it depends on `REMOTE_USER` for namespace selection. The server is expected to run behind an authentication proxy (Traefik, etc.) that resolves the authenticated principal to a namespace and forwards that value as `REMOTE_USER`. Grantory drops back to `_def` if the header is missing, so configure your proxy
to inject it for every authenticated request if you manage namespaces beyond the default.


## Storage

Each namespace is stored as a dedicated sqlite database file in `<database-dir>/<namespace>.db` when `DATABASE` is a directory path.

## What Grantory is not

- Not a secrets manager. Store secret credentials inside your secrets manager (OpenBao, Hashicorp Vault, AWS SecretsManager, etc.) and only forward the path or identifier as payload.
- Not a workflow engine or approval system. It doesn’t schedule jobs, enforce SLAs, or run approvals. It only stores requests and grants.
- Not a policy enforcement point. It doesn’t validate access against policy. You decide what a grant means in your pipeline.
- Not Terraform remote state. It doesn’t replace `terraform_remote_state`, outputs, or dependency ordering between workspaces. It only stores small, explicit signals (requests/registers/grants) between pipelines.

## Example: Gatus external endpoints

This pattern lets any workload register a heartbeat endpoint without needing direct access (or terraform remote state passthrough) to the [Gatus](https://gatus.io/) configuration, assuming that the configuration is templated by terraform.

It has three stages:

1. Producer requests an endpoind: A workload requests a Gatus endpoint (name + optional group).

2. Central Gatus grants tokens: A central "grantor" reads all requests, issues tokens, and writes the final "external‑endpoints" list used by Gatus.

3. Producer uses the granted token: The workload receives its token/URL from Grantory and pushes heartbeats.

### Modules

We assume two modules `grantory_gatus_external_endpoint/request` and `grantory_gatus_external_endpoint/grant` exist.

#### Request `grantory_gatus_external_endpoint/request`

```hcl
resource "grantory_request" "gatus_external_endpoint" {
  host_id = var.host_id
  payload = jsonencode({
    name      = var.name
    group     = var.group
    heartbeat = { interval = var.heartbeat_interval }
  })
  labels = merge(
    { type = "gatus_external_endpoint" },
    var.group == null ? {} : { group = var.group }
  )
}
```

#### Grantor `grantory_gatus_external_endpoint/grant`

```hcl
data "grantory_requests" "gatus_external_endpoints" {
  labels = { type = "gatus_external_endpoint" }
}

data "grantory_request" "details" {
  for_each   = { for r in data.grantory_requests.gatus_external_endpoints.requests : r.request_id => r }
  request_id = each.key
}

resource "random_password" "token" {
  for_each = data.grantory_request.details
  length   = 32
  special  = false
}

resource "grantory_grant" "gatus_external_endpoint" {
  for_each   = data.grantory_request.details
  request_id = each.value.request_id
  payload    = jsonencode({ token = random_password.token[each.key].result, url = var.url })
}

output "external_endpoints" {
  value = [
    for key, req in data.grantory_request.details : merge(
      jsondecode(req.request_payload),
      { token = random_password.token[key].result }
    )
  ]
}
```

### 1) Producer request (workload side)

```hcl
module "gatus_request" {
  source  = "grantory_gatus_external_endpoint/request"
  host_id = grantory_host.host.id
  name    = "my-job@host-01"
  group   = "batch-jobs"
}
```

This only registers the intent. No token is issued yet.

### 2) Grantor (Gatus side)

```hcl
module "gatus_grant" {
  source = "grantory_gatus_external_endpoint/grant"
  url    = "https://status.example.local"
}
```

### 3) Use the granted token (workload side)

After grants are issued, the request resource now has a non‑null `grant_payload`.

In Terraform you typically need to re‑apply so the provider refreshes that field after the grant has been applied.

```hcl
locals {
  gatus_token = try(jsondecode(grantory_request.gatus_external_endpoint.grant_payload).token, null)
  gatus_url   = try(jsondecode(grantory_request.gatus_external_endpoint.grant_payload).url, null)
}
```
