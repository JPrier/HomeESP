# Multi-stage, pinned build of the Home Observatory server, CLI and dashboard.
#   docker build -f deploy/Dockerfile -t home-observatory:0.1.0 .
FROM rust:1.91.1-bookworm AS rust
WORKDIR /src
ARG CARGO_BUILD_JOBS=2
ENV CARGO_BUILD_JOBS=${CARGO_BUILD_JOBS}
COPY Cargo.toml Cargo.lock rust-toolchain.toml ./
COPY crates crates
COPY migrations migrations
COPY configs configs
COPY docs/openapi.json docs/openapi.json
COPY tests/golden tests/golden
COPY tests/fixtures tests/fixtures
RUN cargo build --release --locked -p ho-server -p ho-cli --bins

FROM node:22.12.0-bookworm-slim AS web
WORKDIR /web
COPY dashboard/package.json dashboard/package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY dashboard ./
RUN npm run build

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates && rm -rf /var/lib/apt/lists/* \
 && useradd --system --uid 10001 --home /data --shell /usr/sbin/nologin observatory
COPY --from=rust /src/target/release/observatory-server /usr/local/bin/
COPY --from=rust /src/target/release/observatory-cli /usr/local/bin/
COPY --from=web /web/dist /app/dashboard
USER 10001
WORKDIR /data
ENTRYPOINT ["/usr/local/bin/observatory-server"]
CMD ["--config", "/config/site.yaml", "--log-json"]
