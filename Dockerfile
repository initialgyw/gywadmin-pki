# syntax=docker/dockerfile:1
FROM --platform=$BUILDPLATFORM rust:1.90.0-alpine3.22@sha256:b4b54b176a74db7e5c68fdfe6029be39a02ccbcfe72b6e5a3e18e2c61b57ae26 AS builder

ARG TARGETARCH
ARG TARGETPLATFORM
RUN apk add --no-cache openssl openssl-dev musl-dev build-base
RUN case "$TARGETPLATFORM" in \
        linux/amd64) echo 'x86_64-unknown-linux-musl' > /tmp/rust-target ;; \
        linux/arm64) echo 'aarch64-unknown-linux-musl' > /tmp/rust-target ;; \
        *) echo "unsupported TARGETPLATFORM: $TARGETPLATFORM" >&2; exit 1 ;; \
    esac
RUN rustup target add "$(cat /tmp/rust-target)"
RUN mkdir -p /root/.cargo \
    && printf '[target.x86_64-unknown-linux-musl]\nlinker = "musl-gcc"\n[target.aarch64-unknown-linux-musl]\nlinker = "musl-gcc"\n' > /root/.cargo/config.toml
WORKDIR /work
COPY Cargo.toml Cargo.lock ./
COPY src ./src
COPY tests ./tests
RUN rustup component add rustfmt clippy && cargo fetch --locked
RUN command -v openssl && openssl version
RUN cargo fmt --all -- --check \
    && cargo clippy --locked --all-targets --all-features -- -D warnings \
    && cargo test --locked --all-targets \
    && cargo build --locked --release --target "$(cat /tmp/rust-target)" \
    && test -x "/work/target/$(cat /tmp/rust-target)/release/pki"
RUN cp "/work/target/$(cat /tmp/rust-target)/release/pki" /work/pki
RUN "/work/pki" --help

FROM alpine:3.22 AS runtime

ARG TARGETARCH

RUN apk add --no-cache openssl ca-certificates \
    && addgroup -S -g 10001 pki \
    && adduser -S -D -H -u 10001 -G pki pki \
    && install -d -o 10001 -g 10001 -m 0700 /data/pki \
    && test -x /usr/bin/openssl

COPY --from=builder /work/pki /usr/local/bin/pki
RUN chmod 0755 /usr/local/bin/pki

RUN /usr/local/bin/pki --help >/dev/null \
    && command -v openssl >/dev/null \
    && openssl version >/dev/null \
    && ldd "$(command -v openssl)"

USER 10001:10001
WORKDIR /data/pki
ENTRYPOINT ["/usr/local/bin/pki"]
