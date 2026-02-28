terraform {
  required_providers {
    grantory = {
      source  = "tasansga/grantory"
      version = "0.1.0-test"
    }
    http = {
      source  = "hashicorp/http"
      version = "3.4.2"
    }
  }
}

variable "server_url" {
  type    = string
  default = "http://127.0.0.1:8080"
}

provider "grantory" {
  server = var.server_url
}

data "http" "readyz" {
  url = "${var.server_url}/readyz"
}

locals {
  readyz = jsondecode(data.http.readyz.response_body)
}

output "readyz_backend" {
  value = local.readyz.backend
}

output "readyz_status" {
  value = local.readyz.status
}

resource "grantory_host" "with_labels" {
  labels = {
    env = "inttest"
  }
}

resource "grantory_host" "without_labels" {}

output "grantory_host_with_labels" {
  value = grantory_host.with_labels
}

output "grantory_host_without_labels" {
  value = grantory_host.without_labels
}

resource "grantory_request" "with_labels_payload" {
  host_id = grantory_host.with_labels.host_id
  payload = jsonencode({
    payme = "alot"
  })
  labels = {
    pipeline = "inttest"
  }
}

resource "grantory_request" "without_labels_payload" {
  host_id = grantory_host.without_labels.host_id
}

output "grantory_request_with_labels_payload" {
  value = grantory_request.with_labels_payload
}

output "grantory_request_without_labels_payload" {
  value = grantory_request.without_labels_payload
}

resource "grantory_register" "with_labels_payload" {
  host_id = grantory_host.with_labels.host_id
  unique_key = "register-unique"
  payload = jsonencode({
    source = "inttest-script"
  })
  labels = {
    pipeline = "inttest"
  }
}

resource "grantory_register" "without_labels_payload" {
  host_id = grantory_host.without_labels.host_id
}

output "grantory_register_with_labels_payload" {
  value = grantory_register.with_labels_payload
}

output "grantory_register_without_labels_payload" {
  value = grantory_register.without_labels_payload
}

resource "grantory_grant" "with_payload" {
  request_id = grantory_request.with_labels_payload.id
  payload = jsonencode({
    mygreatpayload = true
  })
}

resource "grantory_grant" "without_payload" {
  request_id = grantory_request.without_labels_payload.id
}

output "grantory_grant_with_payload" {
  value = grantory_grant.with_payload
}

output "grantory_grant_without_payload" {
  value = grantory_grant.without_payload
}

data "grantory_grants" "grants" {
  depends_on = [
    grantory_grant.with_payload,
    grantory_grant.without_payload,
  ]
}

output "data_grantory_grants" {
  value = data.grantory_grants.grants
}

data "grantory_grant" "details" {
  count    = 2
  grant_id = [grantory_grant.with_payload.id, grantory_grant.without_payload.id][count.index]
  depends_on = [
    grantory_grant.with_payload,
    grantory_grant.without_payload,
  ]
}

output "data_grantory_grant_details" {
  value = data.grantory_grant.details
}

data "grantory_hosts" "hosts" {
  depends_on = [
    grantory_host.with_labels,
    grantory_host.without_labels,
  ]
}

output "data_grantory_hosts" {
  value = data.grantory_hosts.hosts
}

data "grantory_registers" "with_labels" {
  labels = {
    pipeline = "inttest"
  }
  depends_on = [
    grantory_register.with_labels_payload,
    grantory_register.without_labels_payload,
  ]
}

output "data_grantory_registers_with_labels" {
  value = data.grantory_registers.with_labels.registers
}

data "grantory_registers" "all" {
  depends_on = [
    grantory_register.with_labels_payload,
    grantory_register.without_labels_payload,
  ]
}

output "data_grantory_registers_all" {
  value = data.grantory_registers.all.registers
}

data "grantory_register" "details" {
  count       = 2
  register_id = [grantory_register.with_labels_payload.id, grantory_register.without_labels_payload.id][count.index]
  depends_on = [
    grantory_register.with_labels_payload,
    grantory_register.without_labels_payload,
  ]
}

output "data_grantory_register_details" {
  value = data.grantory_register.details
}

data "grantory_requests" "with_labels" {
  labels = {
    pipeline = "inttest"
  }
  depends_on = [
    grantory_request.with_labels_payload,
    grantory_request.without_labels_payload,
    grantory_grant.with_payload,
    grantory_grant.without_payload,
  ]
}

output "data_grantory_requests_with_labels" {
  value = data.grantory_requests.with_labels.requests
}

data "grantory_requests" "all" {
  depends_on = [
    grantory_request.with_labels_payload,
    grantory_request.without_labels_payload,
    grantory_grant.with_payload,
    grantory_grant.without_payload,
  ]
}

output "data_grantory_requests_all" {
  value = data.grantory_requests.all.requests
}

data "grantory_request" "details" {
  count      = 2
  request_id = [grantory_request.with_labels_payload.id, grantory_request.without_labels_payload.id][count.index]
  depends_on = [
    grantory_request.with_labels_payload,
    grantory_request.without_labels_payload,
    grantory_grant.with_payload,
    grantory_grant.without_payload,
  ]
}

output "data_grantory_request_details" {
  value = data.grantory_request.details
}
