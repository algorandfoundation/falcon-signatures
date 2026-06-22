FROM golang:1.25 AS builder

WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN mkdir -p build
RUN make build

FROM debian:bookworm-slim

WORKDIR /work

COPY --from=builder /src/build/falcon /usr/local/bin/falcon

ENTRYPOINT ["falcon"]
CMD ["help"]