# syntax=docker/dockerfile:1
FROM rust:1.98.1-bookworm AS build
WORKDIR /build
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
# The Cargo registry and git caches are shared by the WOHP and Bootstrap builds,
# which Compose runs in parallel: lock them. Each workspace has its own target.
RUN --mount=type=cache,id=cargo-registry,target=/usr/local/cargo/registry,sharing=locked \
    --mount=type=cache,id=cargo-git,target=/usr/local/cargo/git,sharing=locked \
    --mount=type=cache,id=wohp-target,target=/build/target,sharing=locked \
    cargo build --release --locked -p wohp --features server --bin wohp-server \
    && install -m 0755 /build/target/release/wohp-server /build/wohp-server

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --uid 10001 --create-home app \
    && install -d -o app -g app -m 0700 /var/lib/wohp-core
COPY --from=build /build/wohp-server /usr/local/bin/wohp-server
USER app
EXPOSE 8787
ENTRYPOINT ["/usr/local/bin/wohp-server"]
