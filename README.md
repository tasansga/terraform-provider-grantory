# Grantory

Grantory implements loose coupling between Terraform/OpenTofu pipelines to decouple producers, consumers, and grantors of runtime configuration. It's a small "control plane" for runtime registrations and requests. It replaces ad‑hoc file/variable wiring and lets workloads publish what they need while other components aggregate and act on those needs.

Producers register or request data into Grantory, consumers read registers or requests, and grantors issue grants.

Links:
- [Homepage](https://github.com/tasansga/terraform-provider-grantory)
- [OpenTofu registry](https://search.opentofu.org/provider/tasansga/grantory/latest)
- [terraform registry](https://registry.terraform.io/providers/tasansga/grantory/latest)

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

## Running the server

Grantory runs as an HTTP server. Configure the data directory, HTTP/HTTPS bind addresses, TLS certificates, and log level via flags or the matching environment variables (`DATA_DIR`, `HTTP_BIND`, `HTTPS_BIND`, `TLS_CERT`, `TLS_KEY`, `LOG_LEVEL`). TLS is only activated if `TLS_CERT` and `TLS_KEY` are set. Set `HTTP_BIND=off` to disable the HTTP listener.

```bash
grantory --data-dir ./data --http-bind 127.0.0.1:8080
```

Defaults: `HTTP_BIND=0.0.0.0:8080`, `HTTPS_BIND=0.0.0.0:8443`.

When TLS is enabled, the server listens on both HTTP and HTTPS using those addresses. `HTTPS_BIND` is only evaluated when `TLS_CERT` and `TLS_KEY` are set.

```bash
grantory --http-bind 127.0.0.1:8080 --https-bind 127.0.0.1:8443 --tls-cert ./cert.pem --tls-key ./key.pem
```

## Docker image

The Grantory server image is published to Docker Hub as [tasansga/grantory](https://hub.docker.com/r/tasansga/grantory).

```bash
docker run --rm -p 8080:8080 -v "$PWD/data:/data" tasansga/grantory:latest
```

Set `DATA_DIR`, `HTTP_BIND`, `HTTPS_BIND`, `TLS_CERT`, `TLS_KEY`, and `LOG_LEVEL` as needed to customize server behavior. The image starts as root, fixes ownership of `DATA_DIR`, then drops privileges to the `grantory` user. If you run the container rootless, ensure the mounted data directory is writable by that user.

## CLI

While Grantory is a terraform-focused tool, there's also a CLI for administrative purposes. The CLI can talk to SQLite directly (`--backend direct`, the default) or route every operation through the HTTP API (`--backend api`). Check `grantory --help` for details.


## Authentication and namespaces

Grantory supports multi-tenancy.

In this setup, when the CLI or Terraform/OpenTofu provider talks to the HTTP API directly, it depends on `REMOTE_USER` for namespace selection. The server is expected to run behind an authentication proxy (Traefik, etc.) that resolves the authenticated principal to a namespace and forwards that value as `REMOTE_USER`. Grantory drops back to `_def` if the header is missing, so configure your proxy
to inject it for every authenticated request if you manage namespaces beyond the default.


## Storage

Each namespace is stored as a dedicated sqlite database file in `<data-dir>/<namespace>.db`.

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
