FROM rust:alpine3.22 AS builder

# Install pre-requisites
RUN apk add build-base gcompat jemalloc-dev

# Create a new directory for our application
WORKDIR /tmp/quincy-build

# Copy the source code into the container
COPY src ./src
COPY Cargo.toml Cargo.lock ./

# Build the application
ARG FEATURES="jemalloc,offload"
RUN cargo build --release --no-default-features --features "${FEATURES}"

FROM alpine:3.22 AS runner

# Create needed directories
RUN mkdir -p /etc/quincy

# Install glibc
RUN apk add gcompat jemalloc libcap-setcap

# Copy the binary from the builder stage
COPY --from=builder /tmp/quincy-build/target/release/quincy-client /tmp/quincy-build/target/release/quincy-server /tmp/quincy-build/target/release/quincy-users /usr/local/bin/

# Add a non-root user
RUN addgroup -S quincy && adduser -S quincy -G quincy
RUN chown -R quincy:quincy /usr/local/bin/quincy-client /usr/local/bin/quincy-server /usr/local/bin/quincy-users

# Add required capabilities to executables
RUN setcap \
    'cap_net_admin,cap_net_bind_service=+ep' /usr/local/bin/quincy-client \
    'cap_net_admin,cap_net_bind_service=+ep' /usr/local/bin/quincy-server \
    'cap_net_admin=+ep' /bin/busybox

# Run under a non-root account
USER quincy

# Set the working directory
WORKDIR /usr/srv/quincy
