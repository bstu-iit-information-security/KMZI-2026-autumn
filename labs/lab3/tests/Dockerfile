FROM ubuntu:22.04 AS builder
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential cmake libboost-all-dev && rm -rf /var/lib/apt/lists/*
WORKDIR /src
COPY . .
RUN cmake -S . -B build -DCMAKE_BUILD_TYPE=Release && cmake --build build -j

FROM ubuntu:22.04
WORKDIR /app
COPY --from=builder /src/build/tests/test_ed25519 /app/tests
ENTRYPOINT ["/app/tests"]