FROM golang:alpine

# Set working directory
WORKDIR /manuka-listener

# Copy project files for build
COPY . .

# Build server
RUN go build

# Run server
CMD ["/manuka-listener/manuka-listener"]