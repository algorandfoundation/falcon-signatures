FROM golang:1.25 AS builder

WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN mkdir -p build
RUN make build

FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates \
 	&& rm -rf /var/lib/apt/lists/*
WORKDIR /work

COPY --from=builder /src/build/falcon /usr/local/bin/falcon

ENTRYPOINT ["falcon"]
CMD ["help"]