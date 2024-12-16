# Build stage for web application
FROM golang:1.22.2-bullseye as web-builder

WORKDIR /app/web
COPY web/go.mod web/go.sum ./
RUN go mod download && go mod tidy

COPY web ./
RUN CGO_ENABLED=0 GOOS=linux go build -o main .

# Final stage
FROM golang:1.22.2-bullseye

# Install build essentials for runtime compilation
RUN apt-get update && apt-get install -y \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy web application executable
COPY --from=web-builder /app/web/main ./web/
COPY web/templates ./web/templates

# Copy ww source code for runtime compilation
COPY ww ./ww

# Copy go.mod files for both directories
COPY web/go.mod web/go.sum ./web/
COPY ww/go.mod ww/go.sum ./ww/

# Expose the port your web app runs on
EXPOSE 8080

# Run the web application
CMD ["./web/main"]