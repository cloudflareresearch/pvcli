FROM rust:1.93-trixie

ENV PATH="/root/.cargo/bin:${PATH}"

RUN apt-get update && apt-get install -y nodejs npm && rm -rf /var/lib/apt/lists/*

WORKDIR /app
