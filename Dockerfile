FROM rust:1.91-slim-bookworm AS builder

WORKDIR /build

RUN apt-get update && \
    apt-get install -y musl-tools protobuf-compiler && \
    rm -rf /var/lib/apt/lists/* && \
    rustup target add aarch64-unknown-linux-musl

# Copy workspace root files
COPY Cargo.toml Cargo.lock ./

# Create crate directory structure for dependency caching
RUN mkdir -p crates/deepslate/src crates/deepslate-mc/src/packets

# Copy crate Cargo.toml files
COPY crates/deepslate/Cargo.toml crates/deepslate/
COPY crates/deepslate-mc/Cargo.toml crates/deepslate-mc/

# Create dummy source files for dependency fetching
RUN echo "fn main() {}" > crates/deepslate/src/main.rs && \
    echo "" > crates/deepslate-mc/src/lib.rs && \
    cargo fetch --locked --target aarch64-unknown-linux-musl

# Copy actual source files
COPY crates/deepslate/build.rs crates/deepslate/
COPY crates/deepslate/proto crates/deepslate/proto
COPY crates/deepslate/src crates/deepslate/src
COPY crates/deepslate-mc/src crates/deepslate-mc/src

RUN cargo build --release --locked --target aarch64-unknown-linux-musl --features mc-1_21_10,mc-1_20_4

FROM scratch

COPY --from=builder /build/target/aarch64-unknown-linux-musl/release/deepslate /deepslate

EXPOSE 25565 25577 25578

ENV RUST_LOG=info

ENTRYPOINT ["/deepslate"]
