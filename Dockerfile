# syntax=docker/dockerfile:1

FROM golang:1.22-alpine AS build
WORKDIR /src
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/keyhole ./cmd/keyhole

FROM gcr.io/distroless/static-debian12:latest
LABEL org.opencontainers.image.source="https://github.com/kaykumar/keyhole"
LABEL org.opencontainers.image.description="Scan for weak and compromised certificate keys"
LABEL org.opencontainers.image.licenses="Apache-2.0"
COPY --from=build /out/keyhole /usr/local/bin/keyhole
ENTRYPOINT ["/usr/local/bin/keyhole"]
