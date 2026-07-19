# Contributing

Thanks for your interest in contributing to a printemps-tokyo project.

## Development

1. Fork / clone the repository
2. Ensure Go 1.23 or newer is installed (`go version`)
3. Create a branch: `git switch -c feat/your-change`
4. Make your change and verify locally:
   ```bash
   gofmt -l .        # must print nothing
   go vet ./...
   go test ./...
   go build ./...
   ```
5. Commit and open a pull request

There are no third-party dependencies: httppeek is built on the Go standard
library only. Please keep it that way unless there is a compelling reason to
add a dependency, and raise it in an issue first.

## Optional local checks

These are not part of CI (they change their lint sets between releases and can
cause spurious failures on green code), but they are useful locally:

```bash
go run honnef.co/go/tools/cmd/staticcheck@latest ./...
```

## Commit messages

[Conventional Commits](https://www.conventionalcommits.org/) are preferred
(`feat:`, `fix:`, `docs:`, `chore:`, `refactor:`, `test:`).

## Pull requests

- Keep one PR focused on a single purpose
- CI (gofmt / vet / test / build) must be green
- Update the README and tests when behavior changes

## Bug reports and requests

Please open an [issue](../../issues) using the templates.
