FROM golang:1.20-alpine AS builder
LABEL org.opencontainers.image.source="https://github.com/interlynk-io/sbomasm"

RUN apk add --no-cache make git
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN make ; make build

FROM scratch
LABEL org.opencontainers.image.source="https://github.com/interlynk-io/sbomasm"
LABEL org.opencontainers.image.description="SBOM Assembler - Assembler for SBOMs"
LABEL org.opencontainers.image.licenses=Apache-2.0

COPY --from=builder /app/build/sbomasm /app/sbomasm
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/

ENTRYPOINT [ "/app/sbomasm"]