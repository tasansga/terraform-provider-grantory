# Grantory

Grantory implements loose coupling between Terraform/OpenTofu pipelines.

Links:
- [Homepage](https://github.com/tasansga/terraform-provider-grantory)
- [OpenTofu registry](https://search.opentofu.org/provider/tasansga/grantory/latest)
- [terraform registry](https://registry.terraform.io/providers/tasansga/grantory/latest)

## Concepts

- **Host** – a remote node that registers labels with Grantory and becomes a reference
  (or owner) of requests/registers.
- **Request** – a workload or permission request emitted by a host.
- **Grant** – the workflow decision for a request. Grants reference a request and can carry
  operator-provided data. The database enforces that every grant belongs to exactly one request
  and that each request can have at most one grant.
- **Register** – a record that stores arbitrary data/labels for a host without expecting a grant.

## Terraform/OpenTofu workflow

Grantory is designed for multi-pipeline automation: one Terraform/OpenTofu pipeline declares a
`grantory_request` (the "producer"), another pipeline or automation run inspects those requests and
creates matching `grantory_grant` resources (the "consumer")

This allows pipelines with requests to act on them (e.g., to rotate secrets or provision proxies).

1. **Request pipeline** – this is typically a terraform or OpenTofu pipeline/module that creates a
   request describing the desired access, user creation, proxy, or other change.
   The request includes specific payload data (e.g., target user info or application
   metadata) and labels for filtering. When you only need to publish metadata without requesting a
   pipeline action, use the register instead.
2. **Grant handler** – watches for requests, filtered by label. It approves them by creating 
   grant resources with additional payload like connection strings or service endpoints.
   This typically runs as cron job or another Terraform/OpenTofu pipeline.


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

## Regenerating provider docs

The terraform docs under `docs` are generated via `tfplugindocs`.
Run the generator so it consumes the templates and examples:

```bash
tfplugindocs generate \
  --provider-dir cmd/terraform-provider-grantory \
  --provider-name grantory \
  --rendered-website-dir docs
```

## Running the server

Grantory runs as a single HTTP service. Configure the data directory, bind address, TLS
certificates, and log level via flags or the matching environment variables (`DATA_DIR`,
`BIND`, `TLS_CERT`, `TLS_KEY`, `LOG_LEVEL`).

```bash
grantory --data-dir ./data --bind 127.0.0.1:8080
```

## CLI (emergency/inspection helper)

While Grantory is a terraform-focused tool, there's also a CLI for administrative purposes.

The CLI can talk to SQLite directly (`--backend direct`, the default) or route every
operation through the HTTP API (`--backend api`).

Check `grantory --help` for details.


## Authentication and namespaces

Grantory supports multi-tenancy.

In this setup, when the CLI or Terraform/OpenTofu provider talks to the HTTP API directly,
it depends on `REMOTE_USER` for namespace selection.
The server is expected to run behind an authentication proxy (Traefik, etc.) that resolves
the authenticated principal to a namespace and forwards that value
as `REMOTE_USER`. Grantory drops back to `_def` if the header is missing, so configure your proxy
to inject it for every authenticated request if you manage namespaces beyond the default.


## Storage

Each namespace is stored as dedicate sqlite database file in `<data-dir>/<namespace>.db`.


## Security

Grantory is not suited to store sensitive payloads. Store secret credentials inside your
secrets manager, be that OpenBao, Hashicorp Vault, AWS SecretsManager or whatever,
and only forward the path to the secret as payload.
