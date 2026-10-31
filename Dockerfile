# syntax=docker/dockerfile:1
FROM golang:1.27-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod go mod download
COPY . .
RUN --mount=type=cache,target=/go/pkg/mod --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 GOFLAGS=-trimpath go build -ldflags="-s -w" -o /out/recipe-manager ./cmd/recipe-manager
RUN mkdir -p /out/data && chown 65532:65532 /out/data && chmod 700 /out/data

# Distroless static: no shell, no package manager, runs as uid 65532 (nonroot).
FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/recipe-manager /recipe-manager
COPY --from=build --chown=65532:65532 /out/data /data
ENV RM_LISTEN=0.0.0.0:8080 RM_DATA_DIR=/data
VOLUME /data
EXPOSE 8080
USER 65532:65532
ENTRYPOINT ["/recipe-manager"]
