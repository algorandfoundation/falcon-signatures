# falcon help

Show help for the CLI or a specific command.

#### Arguments
  - Optional
    - `command`: the subcommand to show help for

## Examples

Show general help:

```bash
falcon help
```

Show help for a specific command:

```bash
falcon help create
```

Run help through Docker:

```bash
docker run --rm falcon help
```

Build and file-mount examples are in [docs/docker.md](docker.md).
