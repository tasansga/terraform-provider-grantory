#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORKDIR="$(mktemp -d)"

echo "using temporary workspace: $WORKDIR"

BIN_DIR="$WORKDIR/provider-bin"
DEV_DIR="$WORKDIR/provider-dev"
TF_BASE_DIR="$WORKDIR/terraform"
PROVIDER_VERSION="${PROVIDER_VERSION:-0.1.0-test}"

mkdir -p "$BIN_DIR" "$DEV_DIR" "$TF_BASE_DIR"

GO_CMD=${GO_CMD:-go}
"$GO_CMD" test ./...
"$GO_CMD" build -o "$BIN_DIR/terraform-provider-grantory" ./cmd/terraform-provider-grantory
"$GO_CMD" build -o "$BIN_DIR/grantory" ./cmd/grantory
cp "$BIN_DIR/terraform-provider-grantory" "$DEV_DIR/terraform-provider-grantory"
cp "$BIN_DIR/terraform-provider-grantory" "$DEV_DIR/terraform-provider-grantory_v${PROVIDER_VERSION}"
chmod +x "$DEV_DIR/terraform-provider-grantory" "$DEV_DIR/terraform-provider-grantory_v${PROVIDER_VERSION}"

CLI_CONFIG="$WORKDIR/terraform.rc"
cat > "$CLI_CONFIG" <<EOF
provider_installation {
  dev_overrides {
    "tasansga/grantory" = "$DEV_DIR"
    "registry.opentofu.org/tasansga/grantory" = "$DEV_DIR"
    "registry.terraform.io/tasansga/grantory" = "$DEV_DIR"
  }
  direct {
    exclude = [
      "tasansga/grantory",
      "registry.opentofu.org/tasansga/grantory",
      "registry.terraform.io/tasansga/grantory",
    ]
  }
}
EOF

export TF_CLI_CONFIG_FILE="$CLI_CONFIG"
export TOFU_CLI_CONFIG_FILE="$CLI_CONFIG"
export TF_IN_AUTOMATION=1

TF_BIN="$(command -v tofu)"
echo "using tofu binary: $TF_BIN"

COMMAND="${1:-apply}"
case "$COMMAND" in
plan|apply|destroy|output) ;;
*)
  echo "subcommand must be one of plan|apply|destroy|output (default apply)" >&2
  exit 1
  ;;
esac

SERVER_PID=""
RAFT_PIDS=()
POSTGRES_CONTAINER=""

cleanup_services() {
  if [[ -n "${SERVER_PID}" ]]; then
    kill "${SERVER_PID}" 2>/dev/null || true
    wait "${SERVER_PID}" 2>/dev/null || true
    SERVER_PID=""
  fi
  if [[ ${#RAFT_PIDS[@]} -gt 0 ]]; then
    for pid in "${RAFT_PIDS[@]}"; do
      kill "$pid" 2>/dev/null || true
      wait "$pid" 2>/dev/null || true
    done
    RAFT_PIDS=()
  fi
  if [[ -n "${POSTGRES_CONTAINER}" ]]; then
    docker rm -f "${POSTGRES_CONTAINER}" >/dev/null 2>&1 || true
    POSTGRES_CONTAINER=""
  fi
}

cleanup() {
  local exit_code=$?
  cleanup_services
  if [[ $exit_code -eq 0 && -n "${WORKDIR:-}" && -d "${WORKDIR}" ]]; then
    rm -rf "$WORKDIR"
  fi
}
trap cleanup EXIT

wait_for_ready() {
  local url="$1"
  local attempts=60
  for _ in $(seq 1 "$attempts"); do
    if command -v curl >/dev/null 2>&1; then
      if curl -fsS "$url/readyz" >/dev/null 2>&1; then
        return 0
      fi
    else
      if "$TF_BIN" -version >/dev/null 2>&1 && command -v wget >/dev/null 2>&1; then
        if wget -qO- "$url/readyz" >/dev/null 2>&1; then
          return 0
        fi
      fi
    fi
    sleep 0.5
  done
  return 1
}

prepare_http_provider() {
  local tf_dir="$1"
  local prep_dir="$WORKDIR/tofu-http"

  if [[ -d "$prep_dir/.terraform/providers" && -f "$prep_dir/.terraform.lock.hcl" ]]; then
    mkdir -p "$tf_dir"
    cp -f "$prep_dir/.terraform.lock.hcl" "$tf_dir/.terraform.lock.hcl"
    mkdir -p "$tf_dir/.terraform"
    cp -R "$prep_dir/.terraform/providers" "$tf_dir/.terraform/"
    return 0
  fi

  if [[ -d "$prep_dir/.terraform/providers" && ! -f "$prep_dir/.terraform.lock.hcl" ]]; then
    rm -rf "$prep_dir"
  fi

  mkdir -p "$prep_dir"
  cat >"$prep_dir/main.tf" <<EOF
terraform {
  required_providers {
    http = {
      source  = "hashicorp/http"
      version = "3.4.2"
    }
  }
}
EOF

  pushd "$prep_dir" >/dev/null
  TF_CLI_CONFIG_FILE= TOFU_CLI_CONFIG_FILE= "$TF_BIN" init -input=false >/dev/null
  popd >/dev/null

  mkdir -p "$tf_dir"
  cp -f "$prep_dir/.terraform.lock.hcl" "$tf_dir/.terraform.lock.hcl"
  mkdir -p "$tf_dir/.terraform"
  cp -R "$prep_dir/.terraform/providers" "$tf_dir/.terraform/"
}

run_tf() {
  local tf_dir="$1"
  local server_url="$2"
  local expected_backend="$3"

  export TF_CLI_CONFIG_FILE="$CLI_CONFIG"
  export TOFU_CLI_CONFIG_FILE="$CLI_CONFIG"

  if [[ ! -f "$TF_CLI_CONFIG_FILE" ]]; then
    echo "missing CLI config at $TF_CLI_CONFIG_FILE" >&2
    exit 1
  fi

  mkdir -p "$tf_dir"
  cp "$SCRIPT_DIR/main.tf" "$tf_dir/main.tf"

  export TF_VAR_server_url="$server_url"

  pushd "$tf_dir" >/dev/null
  if "$TF_BIN" -version 2>/dev/null | head -n 1 | grep -qi "OpenTofu"; then
    prepare_http_provider "$tf_dir"
    :
  else
    TF_CLI_CONFIG_FILE="$CLI_CONFIG" TOFU_CLI_CONFIG_FILE="$CLI_CONFIG" "$TF_BIN" init -input=false >/dev/null
  fi
  case "$COMMAND" in
  plan)
    TF_CLI_CONFIG_FILE="$CLI_CONFIG" TOFU_CLI_CONFIG_FILE="$CLI_CONFIG" "$TF_BIN" plan
    ;;
  apply)
    TF_CLI_CONFIG_FILE="$CLI_CONFIG" TOFU_CLI_CONFIG_FILE="$CLI_CONFIG" "$TF_BIN" apply -input=false -auto-approve
    ;;
  destroy)
    TF_CLI_CONFIG_FILE="$CLI_CONFIG" TOFU_CLI_CONFIG_FILE="$CLI_CONFIG" "$TF_BIN" destroy -auto-approve
    ;;
  output)
    TF_CLI_CONFIG_FILE="$CLI_CONFIG" TOFU_CLI_CONFIG_FILE="$CLI_CONFIG" "$TF_BIN" output
    ;;
  esac

  if [[ "$COMMAND" == "apply" || "$COMMAND" == "output" ]]; then
    if ! command -v jq >/dev/null 2>&1; then
      echo "jq is required to validate readyz_backend output" >&2
      exit 1
    fi
    actual_backend="$(TF_CLI_CONFIG_FILE="$CLI_CONFIG" TOFU_CLI_CONFIG_FILE="$CLI_CONFIG" "$TF_BIN" output -json readyz_backend | jq -r '.')"
    if [[ "$actual_backend" != "$expected_backend" ]]; then
      echo "unexpected readyz_backend output: got $actual_backend, expected $expected_backend" >&2
      exit 1
    fi
    assert_outputs "$TF_BIN" "$CLI_CONFIG" "$expected_backend"
  fi
  popd >/dev/null
}

assert_outputs() {
  local tf_bin="$1"
  local cli_config="$2"
  local expected_backend="$3"

  local outputs_json
  outputs_json="$(TF_CLI_CONFIG_FILE="$cli_config" TOFU_CLI_CONFIG_FILE="$cli_config" "$tf_bin" output -json)"

  echo "$outputs_json" | jq -e ".readyz_backend.value == \"$expected_backend\"" >/dev/null
  echo "$outputs_json" | jq -e '.readyz_status.value == "ok"' >/dev/null

  local host_with_labels
  local host_without_labels
  local request_with_labels_id
  local request_without_labels_id
  local request_with_schema_id
  local register_with_labels_id
  local register_without_labels_id
  local grant_with_payload_id
  local grant_without_payload_id
  local grant_with_schema_id
  local request_schema_definition_id
  local grant_schema_definition_id

  host_with_labels="$(echo "$outputs_json" | jq -r '.grantory_host_with_labels.value.host_id')"
  host_without_labels="$(echo "$outputs_json" | jq -r '.grantory_host_without_labels.value.host_id')"
  request_with_labels_id="$(echo "$outputs_json" | jq -r '.grantory_request_with_labels_payload.value.id')"
  request_without_labels_id="$(echo "$outputs_json" | jq -r '.grantory_request_without_labels_payload.value.id')"
  request_with_schema_id="$(echo "$outputs_json" | jq -r '.grantory_request_with_schema.value.id')"
  register_with_labels_id="$(echo "$outputs_json" | jq -r '.grantory_register_with_labels_payload.value.id')"
  register_without_labels_id="$(echo "$outputs_json" | jq -r '.grantory_register_without_labels_payload.value.id')"
  grant_with_payload_id="$(echo "$outputs_json" | jq -r '.grantory_grant_with_payload.value.id')"
  grant_without_payload_id="$(echo "$outputs_json" | jq -r '.grantory_grant_without_payload.value.id')"
  grant_with_schema_id="$(echo "$outputs_json" | jq -r '.grantory_grant_with_schema.value.id')"
  request_schema_definition_id="$(echo "$outputs_json" | jq -r '.grantory_schema_definition_basic.value.id')"
  grant_schema_definition_id="$(echo "$outputs_json" | jq -r '.grantory_schema_definition_grant.value.id')"

  echo "$outputs_json" | jq -e '.grantory_host_with_labels.value.host_id | length > 0' >/dev/null
  echo "$outputs_json" | jq -e '.grantory_host_without_labels.value.host_id | length > 0' >/dev/null
  echo "$outputs_json" | jq -e '.grantory_host_with_labels.value.labels.env == "inttest"' >/dev/null

  echo "$outputs_json" | jq -e '.grantory_request_with_labels_payload.value.id | length > 0' >/dev/null
  echo "$outputs_json" | jq -e '.grantory_request_without_labels_payload.value.id | length > 0' >/dev/null
  echo "$outputs_json" | jq -e '.grantory_request_with_schema.value.id | length > 0' >/dev/null
  echo "$outputs_json" | jq -e '.grantory_request_with_labels_payload.value.labels.pipeline == "inttest"' >/dev/null
  echo "$outputs_json" | jq -e '.grantory_request_with_labels_payload.value.payload | fromjson == {"payme":"alot"}' >/dev/null
  echo "$outputs_json" | jq -e '.grantory_request_without_labels_payload.value.payload == null' >/dev/null
  echo "$outputs_json" | jq -e '.grantory_schema_definition_basic.value.id | length > 0' >/dev/null
  echo "$outputs_json" | jq -e '.grantory_schema_definition_grant.value.id | length > 0' >/dev/null
  echo "$outputs_json" | jq -e --arg id "$request_schema_definition_id" '.grantory_request_with_schema.value.request_schema_definition_id == $id' >/dev/null
  echo "$outputs_json" | jq -e --arg id "$grant_schema_definition_id" '.grantory_request_with_schema.value.grant_schema_definition_id == $id' >/dev/null
  echo "$outputs_json" | jq -e '.grantory_request_with_schema.value.payload | fromjson == {"name":"schema-request"}' >/dev/null

  echo "$outputs_json" | jq -e '.grantory_register_with_labels_payload.value.id | length > 0' >/dev/null
  echo "$outputs_json" | jq -e '.grantory_register_without_labels_payload.value.id | length > 0' >/dev/null
  echo "$outputs_json" | jq -e '.grantory_register_with_labels_payload.value.unique_key == "register-unique"' >/dev/null
  echo "$outputs_json" | jq -e '.grantory_register_with_labels_payload.value.labels.pipeline == "inttest"' >/dev/null
  echo "$outputs_json" | jq -e '.grantory_register_with_labels_payload.value.payload | fromjson == {"source":"inttest-script"}' >/dev/null
  echo "$outputs_json" | jq -e '.grantory_register_without_labels_payload.value.payload == null' >/dev/null

  echo "$outputs_json" | jq -e '.grantory_grant_with_payload.value.id | length > 0' >/dev/null
  echo "$outputs_json" | jq -e '.grantory_grant_without_payload.value.id | length > 0' >/dev/null
  echo "$outputs_json" | jq -e '.grantory_grant_with_schema.value.id | length > 0' >/dev/null
  echo "$outputs_json" | jq -e '.grantory_grant_with_payload.value.payload | fromjson == {"mygreatpayload":true}' >/dev/null
  echo "$outputs_json" | jq -e '.grantory_grant_without_payload.value.payload == null' >/dev/null
  echo "$outputs_json" | jq -e '.grantory_grant_with_schema.value.payload | fromjson == {"detail":"ok"}' >/dev/null

  echo "$outputs_json" | jq -e --arg id "$host_with_labels" '.data_grantory_hosts.value.hosts | index($id) != null' >/dev/null
  echo "$outputs_json" | jq -e --arg id "$host_without_labels" '.data_grantory_hosts.value.hosts | index($id) != null' >/dev/null
  echo "$outputs_json" | jq -e '.data_grantory_hosts.value.hosts | length == 2' >/dev/null
  echo "$outputs_json" | jq -e --arg id "$host_with_labels" '.data_grantory_host_details.value.host_id == $id' >/dev/null
  echo "$outputs_json" | jq -e '.data_grantory_host_details.value.labels.env == "inttest"' >/dev/null

  echo "$outputs_json" | jq -e '.data_grantory_registers_all.value | length == 2' >/dev/null
  echo "$outputs_json" | jq -e '.data_grantory_registers_with_labels.value | length == 1' >/dev/null
  echo "$outputs_json" | jq -e --arg id "$register_with_labels_id" '.data_grantory_registers_with_labels.value[0].register_id == $id' >/dev/null
  echo "$outputs_json" | jq -e --arg id "$register_with_labels_id" '.data_grantory_register_details.value | map(select(.register_id == $id)) | length == 1' >/dev/null
  echo "$outputs_json" | jq -e --arg id "$register_with_labels_id" '.data_grantory_register_details.value | map(select(.register_id == $id))[0].labels.pipeline == "inttest"' >/dev/null
  echo "$outputs_json" | jq -e --arg id "$register_without_labels_id" '.data_grantory_register_details.value | map(select(.register_id == $id))[0].payload == null' >/dev/null

  echo "$outputs_json" | jq -e '.data_grantory_requests_all.value | length == 3' >/dev/null
  echo "$outputs_json" | jq -e '.data_grantory_requests_with_labels.value | length == 1' >/dev/null
  echo "$outputs_json" | jq -e --arg id "$request_with_labels_id" '.data_grantory_requests_with_labels.value[0].request_id == $id' >/dev/null
  echo "$outputs_json" | jq -e --arg id "$request_with_labels_id" '.data_grantory_request_details.value | map(select(.request_id == $id)) | length == 1' >/dev/null
  echo "$outputs_json" | jq -e --arg id "$request_with_labels_id" '.data_grantory_request_details.value | map(select(.request_id == $id))[0].has_grant == true' >/dev/null
  echo "$outputs_json" | jq -e --arg id "$request_with_labels_id" '.data_grantory_request_details.value | map(select(.request_id == $id))[0].payload | fromjson == {"payme":"alot"}' >/dev/null
  echo "$outputs_json" | jq -e --arg id "$request_with_labels_id" '.data_grantory_request_details.value | map(select(.request_id == $id))[0].grant_payload | fromjson == {"mygreatpayload":true}' >/dev/null
  echo "$outputs_json" | jq -e --arg req "$request_with_labels_id" --arg grant "$grant_with_payload_id" '.data_grantory_request_details.value | map(select(.request_id == $req))[0].grant_id == $grant' >/dev/null
  echo "$outputs_json" | jq -e --arg id "$request_without_labels_id" '.data_grantory_request_details.value | map(select(.request_id == $id))[0].has_grant == true' >/dev/null
  echo "$outputs_json" | jq -e --arg id "$request_without_labels_id" '.data_grantory_request_details.value | map(select(.request_id == $id))[0].payload == null' >/dev/null
  echo "$outputs_json" | jq -e --arg id "$request_without_labels_id" '.data_grantory_request_details.value | map(select(.request_id == $id))[0].grant_payload == null' >/dev/null
  echo "$outputs_json" | jq -e --arg req "$request_without_labels_id" --arg grant "$grant_without_payload_id" '.data_grantory_request_details.value | map(select(.request_id == $req))[0].grant_id == $grant' >/dev/null

  echo "$outputs_json" | jq -e '.data_grantory_grants.value.grants | length == 3' >/dev/null
  echo "$outputs_json" | jq -e --arg id "$grant_with_payload_id" '.data_grantory_grants.value.grants | map(.grant_id) | index($id) != null' >/dev/null
  echo "$outputs_json" | jq -e --arg id "$grant_without_payload_id" '.data_grantory_grants.value.grants | map(.grant_id) | index($id) != null' >/dev/null
  echo "$outputs_json" | jq -e --arg id "$grant_with_schema_id" '.data_grantory_grants.value.grants | map(.grant_id) | index($id) != null' >/dev/null
  echo "$outputs_json" | jq -e --arg id "$grant_with_payload_id" '.data_grantory_grant_details.value | map(select(.grant_id == $id)) | length == 1' >/dev/null
  echo "$outputs_json" | jq -e --arg id "$grant_with_payload_id" '.data_grantory_grant_details.value | map(select(.grant_id == $id))[0].payload | fromjson == {"mygreatpayload":true}' >/dev/null
  echo "$outputs_json" | jq -e --arg id "$grant_without_payload_id" '.data_grantory_grant_details.value | map(select(.grant_id == $id))[0].payload == null' >/dev/null
}

start_server() {
  local database="$1"
  local port="$2"
  local log_file="$3"

  DATABASE="$database" "$BIN_DIR/grantory" serve --http-bind "127.0.0.1:${port}" >"$log_file" 2>&1 &
  SERVER_PID=$!
  local base_url="http://127.0.0.1:${port}"
  if ! wait_for_ready "$base_url"; then
    echo "server failed to become ready (log: $log_file)" >&2
    return 1
  fi
}

run_sqlite() {
  local sqlite_dir="$WORKDIR/sqlite-data"
  local server_port="${SQLITE_PORT:-18080}"
  local tf_dir="$TF_BASE_DIR/sqlite"
  local log_file="$WORKDIR/server-sqlite.log"

  mkdir -p "$sqlite_dir"
  start_server "$sqlite_dir" "$server_port" "$log_file"
  run_tf "$tf_dir" "http://127.0.0.1:${server_port}" "sqlite"
  cleanup_services
}

run_postgres() {
  if ! command -v docker >/dev/null 2>&1; then
    echo "docker is required to run postgres inttest" >&2
    exit 1
  fi

  local pg_port="${POSTGRES_PORT:-55432}"
  local pg_user="grantory"
  local pg_pass="grantory"
  local pg_db="grantory"
  local server_port="${POSTGRES_SERVER_PORT:-18081}"
  local tf_dir="$TF_BASE_DIR/postgres"
  local log_file="$WORKDIR/server-postgres.log"

  POSTGRES_CONTAINER="grantory-inttest-postgres-$RANDOM"
  docker run --rm -d \
    --name "$POSTGRES_CONTAINER" \
    -e POSTGRES_USER="$pg_user" \
    -e POSTGRES_PASSWORD="$pg_pass" \
    -e POSTGRES_DB="$pg_db" \
    -p "${pg_port}:5432" \
    postgres:16-alpine >/dev/null

  local ready="false"
  for _ in $(seq 1 60); do
    if docker exec "$POSTGRES_CONTAINER" pg_isready -U "$pg_user" >/dev/null 2>&1; then
      ready="true"
      break
    fi
    sleep 0.5
  done
  if [[ "$ready" != "true" ]]; then
    echo "postgres failed to become ready" >&2
    exit 1
  fi

  local dsn="postgres://${pg_user}:${pg_pass}@127.0.0.1:${pg_port}/${pg_db}?sslmode=disable"
  POSTGRES_DSN="$dsn" "$GO_CMD" test -tags=postgres ./internal/storage
  start_server "$dsn" "$server_port" "$log_file"
  run_tf "$tf_dir" "http://127.0.0.1:${server_port}" "postgres"
  cleanup_services
}

run_raft() {
  local base_dir="$WORKDIR/raft-data"
  local tf_dir="$TF_BASE_DIR/raft"
  local log_file_prefix="$WORKDIR/server-raft"
  local base_port="${RAFT_BASE_PORT:-18080}"

  local node1_http=$((base_port + 2))
  local node1_raft=$((base_port + 3))
  local node2_http=$((base_port + 4))
  local node2_raft=$((base_port + 5))
  local node3_http=$((base_port + 6))
  local node3_raft=$((base_port + 7))

  mkdir -p "$base_dir/node1" "$base_dir/node2" "$base_dir/node3"
  local peers="node-1=127.0.0.1:${node1_raft},node-2=127.0.0.1:${node2_raft},node-3=127.0.0.1:${node3_raft}"
  local peer_http_addrs="node-1=http://127.0.0.1:${node1_http},node-2=http://127.0.0.1:${node2_http},node-3=http://127.0.0.1:${node3_http},127.0.0.1:${node1_raft}=http://127.0.0.1:${node1_http},127.0.0.1:${node2_raft}=http://127.0.0.1:${node2_http},127.0.0.1:${node3_raft}=http://127.0.0.1:${node3_http}"

  for i in 1 2 3; do
    local node_http_port=$((base_port + 2 * i))
    local node_raft_port=$((base_port + 1 + 2 * i))
    DATABASE="$base_dir/node${i}" "$BIN_DIR/grantory" serve \
      --http-bind "127.0.0.1:${node_http_port}" \
      --raft-bind "127.0.0.1:${node_raft_port}" \
      --raft-advertise "127.0.0.1:${node_raft_port}" \
      --raft-node-id "node-${i}" \
      --raft-bootstrap-expect 3 \
      --raft-peers "$peers" \
      --raft-peer-http-addrs "$peer_http_addrs" \
      >"${log_file_prefix}-node${i}.log" 2>&1 &
    RAFT_PIDS+=($!)
  done

  # Wait for all nodes to become ready
  for i in 1 2 3; do
    local node_http_port=$((base_port + 2 * i))
    if ! wait_for_ready "http://127.0.0.1:${node_http_port}"; then
      echo "raft node ${i} failed to become ready (log: ${log_file_prefix}-node${i}.log)" >&2
      cleanup_services
      return 1
    fi
  done

  # Wait for cluster leader election and find a follower node to target with OpenTofu/Terraform
  local leader_url=""
  local follower_url=""
  local attempts=60
  for _ in $(seq 1 "$attempts"); do
    local leaders=0
    local f_url=""
    local l_url=""
    for i in 1 2 3; do
      local node_http_port=$((base_port + 2 * i))
      local node_url="http://127.0.0.1:${node_http_port}"
      local status_json
      if status_json="$(curl -fsS "${node_url}/api/v1/cluster/status" 2>/dev/null)"; then
        local is_leader
        is_leader="$(echo "$status_json" | jq -r '.is_leader')"
        if [[ "$is_leader" == "true" ]]; then
          leaders=$((leaders + 1))
          l_url="$node_url"
        else
          f_url="$node_url"
        fi
      fi
    done
    if [[ "$leaders" -eq 1 && -n "$f_url" && -n "$l_url" ]]; then
      leader_url="$l_url"
      follower_url="$f_url"
      break
    fi
    sleep 0.5
  done

  if [[ -z "$follower_url" ]]; then
    echo "raft cluster failed to elect leader and stabilize (logs in $WORKDIR)" >&2
    cleanup_services
    return 1
  fi

  echo "raft cluster online: leader=$leader_url, targeting follower=$follower_url"
  run_tf "$tf_dir" "$follower_url" "sqlite"
  cleanup_services
}

TARGET="${TARGET:-all}"

case "$TARGET" in
sqlite)
  run_sqlite
  ;;
raft)
  run_raft
  ;;
postgres)
  run_postgres
  ;;
all)
  run_sqlite
  run_raft
  run_postgres
  ;;
*)
  echo "unknown TARGET $TARGET (supported: sqlite, raft, postgres, all)" >&2
  exit 1
  ;;
esac
