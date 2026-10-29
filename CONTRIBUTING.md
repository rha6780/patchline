# Contributing to Patchline

English | [한국어](CONTRIBUTING.ko.md)

Thanks for your interest in Patchline. Bug reports, documentation fixes and pull requests are all welcome.

## Before you start

- **Bugs**: open an issue with what you did, what you expected and what happened. Include the Patchline version (`git describe`), the Dependency-Track version and the relevant log lines (`PATCHLINE_LOG_LEVEL=debug`). Remove tokens, hostnames and other internal details.
- **Features and larger changes**: open an issue first, so the approach can be agreed on before you spend time on code. Check the [scope](docs/how-it-works.md#out-of-scope) too.
- **Security issues**: do not open a public issue. Report them privately through **Security → Report a vulnerability** on GitHub.

## Development setup

You need Go (the version in [`go.mod`](go.mod)) and, for the demo, Docker with at least 8 GB of memory.

```sh
git clone https://github.com/rha6780/patchline.git
cd patchline
make build && ./bin/patchline    # :8080, no setup needed
make test
```

For an end-to-end run with Dependency-Track, use the [compose demo](deploy/compose/README.md) (`make demo-up`).

| Command | |
|---|---|
| `make build` | Build `bin/patchline` |
| `make run` | Build and run |
| `make test` | `go test ./...` |
| `make vet` | `go vet ./...` |
| `make fmt` | `gofmt -w .` |
| `make docker` | Build the container image |
| `make demo-up` / `demo-down` / `demo-logs` | Compose demo |

## Pull requests

1. Fork the repository and create a branch from `main`.
2. Keep each pull request to one change. Add or update tests for behavior changes.
3. Run the same checks as CI before pushing:

   ```sh
   gofmt -l .            # must print nothing
   go vet ./...
   go test -race ./...
   ```

4. Write commit messages in the [Conventional Commits](https://www.conventionalcommits.org/) style used in the history: `feat:`, `fix:`, `docs:`, `chore:`, `refactor:`, `test:`, with a short imperative summary.
5. Describe what changed and why in the pull request, and link the issue.

### Documentation and translations

Documentation and UI text are kept in English and Korean.

- When you change a document, update both `*.md` and `*.ko.md`. If you can only write one language, say so in the pull request and it will be translated in review.
- UI and Slack text lives in [`internal/i18n/catalog.go`](internal/i18n/catalog.go); add every new key in both languages.
- Configuration changes go into [docs/configuration.md](docs/configuration.md); behavior changes into [docs/how-it-works.md](docs/how-it-works.md) or the [integration guides](docs/README.md).

## Project layout

```
patchline/
├── cmd/patchline/          # main entrypoint
├── internal/
│   ├── auth/               # OIDC sign-in, sessions, access policy
│   ├── config/             # environment variables
│   ├── server/             # HTTP: webhook inbox, internal API, UI routes
│   ├── finding/            # model, state transitions, event log
│   ├── policy/             # severity + SLA rules
│   ├── inventory/          # Git-managed service inventory
│   ├── i18n/               # English and Korean text
│   ├── intake/             # inbox processor: webhook deliveries → findings
│   ├── notify/             # notifier: one message per finding, updates, thread history
│   ├── source/             # inputs: dependencytrack, gitea, kev
│   ├── sink/               # outputs: slack, console
│   ├── store/              # persistence + migrations
│   ├── version/            # best-effort cross-ecosystem version comparison
│   ├── job/                # scheduled jobs: SLA evaluation, reminders, KEV refresh
│   └── web/                # server-rendered pages + embedded CSS
├── examples/               # sample inventory, policy, access policy, SBOM
├── deploy/compose/         # docker compose demo
├── deploy/self-hosted/     # docker compose for on-premises / local use
└── docs/                   # how it works, configuration, integration guides
```

### Tech stack

| Area | Choice |
|---|---|
| Language | Go |
| HTTP | `net/http` (Go 1.22+ routing) |
| UI | `html/template`, server-rendered, no JavaScript |
| Database | SQLite (`ncruces/go-sqlite3`, pure Go, no cgo), migrations with `goose` |
| Configuration | environment variables, inventory in YAML (`go.yaml.in/yaml/v3`) |
| Background work | in-process workers: inbox processor and notifier (no queue or Redis) |
| Integrations | small standard-library HTTP clients for Dependency-Track and the Slack Web API |
| Versions | built-in best-effort comparison across Maven, npm, PyPI and Go styles |
| Logging | `log/slog` |
| Container | distroless, non-root |

New dependencies need a good reason; the standard library is preferred. Database changes go in a new migration under `internal/store/migrations/`; never edit an existing one.

## License

By contributing, you agree that your contributions are licensed under the [Apache License 2.0](LICENSE), the same license as the project.
