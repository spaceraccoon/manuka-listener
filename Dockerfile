FROM golang:alpine as build

# Set working directory
WORKDIR /manuka-listener

# Copy project files for build
COPY . .

# Build server
RUN go build

# Start new stage
FROM alpine:latest

# Copy build
COPY --from=build /manuka-listener/manuka-listener .

# Run server
CMD "./manuka-listener"