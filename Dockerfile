# SPDX-License-Identifier: BUSL-1.1
# Copyright 2026 Ryan Gillespie / Optitransfer
# Multi-stage build: compile acfa-rs (pinned, unmodified) and the JSON bridge from source,
# then run the Gradio app on python:3.12-slim. Lean 4 is installed so the Formal-proofs tab runs live.
FROM rust:1-bookworm AS rust
ARG ACFA_REV=d19fb56b043ddad3ac0448ed9ceede51ba6c2c47
WORKDIR /src
COPY bridge/Cargo.toml bridge/Cargo.lock bridge/
COPY bridge/src bridge/src
RUN cargo build --release --locked --manifest-path bridge/Cargo.toml \
 && cargo install --git https://github.com/mgillr/acfa-rs --rev ${ACFA_REV} acfa-receipt --bin acfa-verify --root /out \
 && cp bridge/target/release/acfa-bridge /out/bin/

FROM python:3.12-slim
RUN apt-get update && apt-get install -y --no-install-recommends curl ca-certificates git perl && rm -rf /var/lib/apt/lists/*
RUN useradd -m -u 1000 user
USER user
ENV HOME=/home/user PATH=/home/user/.elan/bin:/home/user/.local/bin:$PATH \
    ACFA_BRIDGE_BIN=/usr/local/bin/acfa-bridge ACFA_VERIFY_BIN=/usr/local/bin/acfa-verify PYTHONUNBUFFERED=1
WORKDIR /home/user/app
COPY --chown=user requirements.txt .
RUN pip install --no-cache-dir --user -r requirements.txt
COPY --chown=user proofs/lean-toolchain proofs/
RUN curl -sSf https://raw.githubusercontent.com/leanprover/elan/master/elan-init.sh | sh -s -- -y --default-toolchain $(cat proofs/lean-toolchain)
COPY --from=rust /out/bin/acfa-verify /out/bin/acfa-bridge /usr/local/bin/
COPY --chown=user . .
RUN bash proofs/check.sh > proofs/BUILD_LOG.txt 2>&1; tail -n 1 proofs/BUILD_LOG.txt
EXPOSE 7860
CMD ["python", "app.py"]
