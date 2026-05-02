Your goal is to audit and update any vulnerable dependencies in this project.

Start by detecting what type of project this is, then follow the appropriate steps below.

---

## 1. Detect project type

Check for the presence of these files to determine which ecosystems apply (a project may have more than one):

| File | Ecosystem |
|---|---|
| `package.json` / `package-lock.json` | Node.js / npm |
| `yarn.lock` | Node.js / Yarn |
| `pnpm-lock.yaml` | Node.js / pnpm |
| `requirements.txt` / `Pipfile` / `pyproject.toml` | Python |
| `Gemfile` / `Gemfile.lock` | Ruby |
| `go.mod` / `go.sum` | Go |
| `Cargo.toml` / `Cargo.lock` | Rust |
| `pom.xml` / `build.gradle` | Java (Maven / Gradle) |
| `composer.json` | PHP |
| `*.csproj` / `packages.config` | .NET / NuGet |

If none of these exist, report that no dependency manifest was found and stop.

---

## 2. Run the audit for each detected ecosystem

### Node.js (npm)
```bash
npm audit
npm audit fix
```
If breaking changes are needed: `npm audit fix --force` (confirm with user first).

### Node.js (Yarn)
```bash
yarn audit
yarn upgrade
```

### Node.js (pnpm)
```bash
pnpm audit
pnpm audit --fix
```

### Python
```bash
pip audit                        # pip 23+ built-in
# or: safety check -r requirements.txt
pip install --upgrade -r requirements.txt
```
If `pip audit` is not available: `pip install pip-audit && pip-audit`.

### Ruby
```bash
bundle audit check --update
bundle update
```
If `bundler-audit` is not installed: `gem install bundler-audit`.

### Go
```bash
govulncheck ./...
go get -u ./...
go mod tidy
```
If `govulncheck` is not installed: `go install golang.org/x/vuln/cmd/govulncheck@latest`.

### Rust
```bash
cargo audit
cargo update
```
If `cargo-audit` is not installed: `cargo install cargo-audit`.

### Java (Maven)
```bash
mvn org.owasp:dependency-check-maven:check
mvn versions:use-latest-releases
```

### Java (Gradle)
```bash
./gradlew dependencyCheckAnalyze
./gradlew dependencyUpdates
```

### PHP (Composer)
```bash
composer audit
composer update
```

### .NET (NuGet)
```bash
dotnet list package --vulnerable
dotnet outdated
```

---

## 3. Run tests after applying fixes

After updates, run the project's test suite to verify nothing broke:

- **Node.js:** `npm test` / `yarn test` / `pnpm test`
- **Python:** `pytest` or `python -m unittest`
- **Ruby:** `bundle exec rspec` or `bundle exec rake test`
- **Go:** `go test ./...`
- **Rust:** `cargo test`
- **Java:** `mvn test` / `./gradlew test`
- **PHP:** `composer test` or `./vendor/bin/phpunit`
- **.NET:** `dotnet test`

If no test command is configured, note that and skip this step.

---

## 4. Report findings

Summarise the results in this format:

- Ecosystems detected
- Vulnerabilities found (count by severity: Critical / High / Moderate / Low)
- Packages updated
- Any vulnerabilities that could NOT be auto-fixed (manual action required)
- Test result (passed / failed / skipped)