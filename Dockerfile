# syntax=docker/dockerfile:1
FROM golang:1.25.5-bookworm AS build

RUN apt-get update \
    && apt-get install -y --no-install-recommends gcc libc6-dev libsqlite3-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download

COPY . ./

ARG TARGETOS
ARG TARGETARCH
ARG VERSION=dev
ARG COMMIT=unknown
ENV CGO_ENABLED=1
RUN GOOS=${TARGETOS:-linux} GOARCH=${TARGETARCH:-amd64} \
    go build -ldflags "-s -w -X github.com/tasansga/terraform-provider-grantory/internal/cli.Version=${VERSION} -X github.com/tasansga/terraform-provider-grantory/internal/cli.Commit=${COMMIT}" \
    -o /out/grantory ./cmd/grantory

FROM debian:bookworm-slim

RUN apt-get update \
  && apt-get install -y --no-install-recommends ca-certificates libsqlite3-0 gosu \
  && rm -rf /var/lib/apt/lists/*

RUN groupadd -r grantory && useradd -r -g grantory -u 10001 grantory
RUN mkdir -p /data && chown -R grantory:grantory /data

COPY --from=build /out/grantory /usr/local/bin/grantory
COPY docker/entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh

ENV DATA_DIR=/data
EXPOSE 8080 8443
VOLUME ["/data"]

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
CMD ["grantory", "serve"]
