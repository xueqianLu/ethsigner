# Stage 1: Build the Go binary using a build image
FROM golang:1.21-alpine AS builder

# Set the working directory inside the container
WORKDIR /app

# Copy go.mod and go.sum files to download dependencies first
# This leverages Docker's layer caching
COPY go.mod go.sum ./
RUN go mod download

# Copy the entire source code
COPY . .

# Build the Go application
# CGO_ENABLED=0 creates a static binary, which is important for running in a minimal Alpine image
# -ldflags="-s -w" strips debug information, reducing the binary size
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o /app/signer ./cmd/signer

# Stage 2: Create the final, minimal production image
FROM alpine:latest

# Set the working directory
WORKDIR /app

# Copy the built binary from the builder stage
COPY --from=builder /app/signer .

# Copy the configuration file.
# The actual config will be mounted as a volume in docker-compose,
# but this ensures the file exists.
COPY config.example.yaml /app/config.yaml

# Expose the port the application will run on
EXPOSE 8080

# The command to run when the container starts
CMD ["./signer"]

