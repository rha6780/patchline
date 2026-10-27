# syntax=docker/dockerfile:1

FROM golang:1.27-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG VERSION=dev
RUN CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X main.version=${VERSION}" -o /out/patchline ./cmd/patchline \
 && mkdir -p /out/data

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/patchline /patchline
COPY --from=build --chown=65532:65532 /out/data /data
ENV PATCHLINE_ADDR=:8080 \
    PATCHLINE_DB_PATH=/data/patchline.db
VOLUME ["/data"]
EXPOSE 8080
USER 65532:65532
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s CMD ["/patchline", "healthcheck"]
ENTRYPOINT ["/patchline"]
