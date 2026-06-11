# Docker usage

Build and run the `falcon` CLI with Docker.

## Build the image

From the repository root:

```bash
docker build -t falcon .
```

This builds the CLI inside a Go 1.25 container and produces a runtime image with the `falcon` binary as its entrypoint.

## Run commands

Show help:

```bash
docker run --rm falcon help
```

Show the version:

```bash
docker run --rm falcon version
```

## Work with local files

Most commands read or write files. Mount a host directory into `/work` and run the container from there:

```bash
docker run --rm -v "$PWD:/work" -w /work falcon create --out mykeys.json
docker run --rm -v "$PWD:/work" -w /work falcon sign --key mykeys.json --msg "hello world" --out hello.sig
docker run --rm -v "$PWD:/work" -w /work falcon verify --key mykeys.json --msg "hello world" --sig hello.sig
```

## Notes

- The container entrypoint is `falcon`, so anything after the image name is passed directly to the CLI.
- On Windows PowerShell, use `${PWD}:/work` instead of `$PWD:/work` if needed:

```powershell
docker run --rm -v "${PWD}:/work" -w /work falcon help
```