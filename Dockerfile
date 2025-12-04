FROM rust:1.91-slim-bookworm AS builder

WORKDIR /build

RUN apt-get update && \
    apt-get install -y musl-tools && \
    rm -rf /var/lib/apt/lists/* && \
    rustup target add aarch64-unknown-linux-musl

COPY Cargo.toml Cargo.lock ./
RUN mkdir src && echo "fn main() {}" > src/main.rs && \
    cargo fetch --locked --target aarch64-unknown-linux-musl

COPY src ./src
RUN cargo build --release --locked --target aarch64-unknown-linux-musl

FROM scratch

COPY --from=builder /build/target/aarch64-unknown-linux-musl/release/deepslate /deepslate

EXPOSE 25565

ENV RUST_LOG=info

ENTRYPOINT ["/deepslate"]
