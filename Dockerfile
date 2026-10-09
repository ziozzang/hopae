# syntax=docker/dockerfile:1
#
# Multi-stage build of a static musl binary (rusqlite bundled SQLite, rustls
# with bundled roots: no system libraries, no CA bundle needed at run time).
#
#   docker build --network=host -t hopae:dev .
#
# The final image holds the binary and an empty state directory, nothing else.

FROM rust:1.96-bookworm AS build
RUN apt-get update \
 && apt-get install -y --no-install-recommends musl-tools \
 && rm -rf /var/lib/apt/lists/*
WORKDIR /src

# Pick the musl target that matches the build machine.
RUN case "$(uname -m)" in \
      x86_64)  echo x86_64-unknown-linux-musl  > /target ;; \
      aarch64) echo aarch64-unknown-linux-musl > /target ;; \
      *) echo "unsupported architecture $(uname -m)" >&2; exit 1 ;; \
    esac \
 && rustup target add "$(cat /target)"

# Dependencies first, so a source-only change reuses the cached layer.
COPY Cargo.toml Cargo.lock build.rs ./
RUN mkdir -p src/store/migrations \
 && echo 'fn main() {}' > src/main.rs \
 && echo '' > src/lib.rs \
 && cargo build --release --locked --target "$(cat /target)" \
 ; rm -rf src

COPY build.rs Cargo.toml Cargo.lock ./
COPY src ./src
COPY templates ./templates
RUN touch src/main.rs src/lib.rs \
 && cargo build --release --locked --target "$(cat /target)" --bin hopae \
 && install -D "target/$(cat /target)/release/hopae" /out/hopae \
 && install -d -m 0700 -o 1000 -g 1000 /out/state

FROM scratch
COPY --from=build --chmod=0555 /out/hopae /hopae
COPY --from=build --chown=1000:1000 /out/state /var/lib/hopae
USER 1000:1000
WORKDIR /var/lib/hopae
# Portal 127.0.0.1:8700 and gateway 127.0.0.1:8701 by default; see deploy/.
ENTRYPOINT ["/hopae"]
CMD ["run", "--config", "/etc/hopae/hopae.json"]
