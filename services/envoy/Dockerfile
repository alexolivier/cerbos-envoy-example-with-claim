# syntax=docker/dockerfile:1
FROM golang:1.24 AS adapter-build
WORKDIR /src
COPY ./adapter/go.mod ./adapter/go.sum ./
RUN go mod download
COPY ./adapter/ ./
RUN CGO_ENABLED=0 go build -o /out/envoy-adapter ./...

FROM envoyproxy/envoy:v1.30-latest
RUN apt-get update && apt-get install -y --no-install-recommends tini \
    && rm -rf /var/lib/apt/lists/*
COPY --from=adapter-build /out/envoy-adapter /usr/local/bin/envoy-adapter
COPY ./start-envoy.sh /usr/local/bin/start-envoy.sh
RUN chmod +x /usr/local/bin/start-envoy.sh
ENTRYPOINT ["/usr/bin/tini","--","/usr/local/bin/start-envoy.sh"]
