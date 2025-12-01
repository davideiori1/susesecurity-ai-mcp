# Build Stage
FROM golang:1.24-alpine AS builder
WORKDIR /app

# Copy dependency files first for caching
COPY go.mod go.sum ./
RUN go mod download

# Copy the source code
COPY . .

# Build the binary
# We output it as 'mcp-server'
RUN CGO_ENABLED=0 GOOS=linux go build -o mcp-server main.go

# Runtime Stage
FROM alpine:latest
WORKDIR /app

# Install basic CA certs just in case
RUN apk --no-cache add ca-certificates

# Copy the binary from builder
COPY --from=builder /app/mcp-server .

# Expose the port defined in your main.go (9092)
EXPOSE 9092

# Run the server
CMD ["./mcp-server"]