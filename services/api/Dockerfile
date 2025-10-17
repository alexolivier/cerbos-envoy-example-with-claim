# syntax=docker/dockerfile:1
FROM golang:1.24 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY main.go ./
COPY openapi.json ./
RUN CGO_ENABLED=0 go build -o /bin/api ./

FROM gcr.io/distroless/base-debian12
COPY --from=build /bin/api /bin/api
COPY --from=build /src/openapi.json /openapi.json
USER nonroot:nonroot
EXPOSE 8080
ENTRYPOINT ["/bin/api"]
