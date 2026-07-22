FROM rust:1.97.1-trixie AS builder
ARG ENTRYPOINT
RUN : "${ENTRYPOINT:?ENTRYPOINT build-arg is required}"
WORKDIR /usr/src/app
COPY Cargo.toml Cargo.lock .
COPY src src
RUN cargo install --bin ${ENTRYPOINT} --path .

FROM gcr.io/distroless/cc-debian13
ARG ENTRYPOINT
LABEL org.opencontainers.image.source="https://github.com/michaelbeaumont/oidc-issuer-config-sync"

COPY --from=builder /usr/local/cargo/bin/${ENTRYPOINT} /usr/local/bin/entrypoint
ENTRYPOINT ["entrypoint"]
