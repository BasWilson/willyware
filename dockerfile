# Build stage
FROM golang:1.21 as builder

# Install build essentials
RUN apt-get update && apt-get install -y \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Copy both ww and web directories
COPY ww ./ww
COPY web ./web

# Set working directory to web
WORKDIR /app/web

# Download dependencies
RUN go mod download

# Build the web application
RUN CGO_ENABLED=0 GOOS=linux go build -o main .

# Final stage
FROM golang:1.21

# Install build essentials for building Go apps at runtime
RUN apt-get update && apt-get install -y \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy the built executable from builder stage
COPY --from=builder /app/web/main .

# Copy both ww and web directories for runtime access
COPY ww ./ww
COPY web ./web

# Expose the port your web app runs on
EXPOSE 8080

# Run the web application
CMD ["./main"]