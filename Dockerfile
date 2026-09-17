# syntax=docker/dockerfile:1
FROM --platform=$BUILDPLATFORM rust:1.90.0-alpine3.22@sha256:b4b54b176a74db7e5c68fdfe6029be39a02ccbcfe72b6e5a3e18e2c61b57ae26 AS builder

ARG TARGETARCH
RUN apk add --no-cache openssl openssl-dev musl-dev build-base
WORKDIR /work
COPY Cargo.toml Cargo.lock ./
COPY src ./src
COPY tests ./tests
RUN rustup component add rustfmt clippy && cargo fetch --locked
RUN command -v openssl && openssl version
RUN cargo fmt --all -- --check \
    && cargo clippy --locked --all-targets --all-features -- -D warnings \
    && cargo test --locked --all-targets \
    && cargo build --locked --release \
    && test -x /work/target/release/pki
RUN /work/target/release/pki --help

FROM alpine:3.22 AS runtime

RUN apk add --no-cache openssl ca-certificates \
    && addgroup -S -g 10001 pki \
    && adduser -S -D -H -u 10001 -G pki pki \
    && install -d -o 10001 -g 10001 -m 0700 /data/pki \
    && test -x /usr/bin/openssl

COPY --from=builder /work/target/release/pki /usr/local/bin/pki

RUN /usr/local/bin/pki --help >/dev/null \
    && command -v openssl >/dev/null \
    && openssl version >/dev/null \
    && ldd "$(command -v openssl)"

USER 10001:10001
WORKDIR /data/pki
ENTRYPOINT ["/usr/local/bin/pki"]
