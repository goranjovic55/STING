---
name: ci-cd
description: Load when editing .github/workflows/*.yml files, deploy scripts, or managing GitHub Actions pipelines. Provides workflow patterns for build, test, and deploy automation.
---

# CI/CD

## Merged Skills
- **github-actions**: Workflow syntax, jobs, steps, actions
- **deployment**: Build, push, deploy automation

## ⚠️ Critical Gotchas

| Category | Pattern | Solution |
|----------|---------|----------|
| Secret leak | Secrets printed in logs | Use `::add-mask::` for dynamic secrets |
| Silent failure | Workflow fails without error | Add explicit `permissions:` block |
| Cache stale | Old dependencies used | Update cache key when deps change |
| No path filter | Every push triggers workflow | Add `paths:` to filter relevant changes |
| Missing checkout | Files not available | Add `actions/checkout@v4` as first step |
| Wrong context | Secrets not available in PR | Use `pull_request_target` carefully |

## Rules

| Rule | Pattern |
|------|---------|
| Path filters | Use `paths:` to skip irrelevant runs |
| Minimal permissions | Explicit `permissions:` block, least privilege |
| Never hardcode | Use `${{ secrets.* }}` for credentials |
| Cache dependencies | `actions/cache` for node_modules, pip cache |
| Fail fast | Set `fail-fast: true` in matrix builds |

## Avoid

| ❌ Bad | ✅ Good |
|--------|---------|
| No paths filter | `paths: ['src/**', '.github/workflows/*.yml']` |
| No permissions block | `permissions: { contents: read }` |
| Hardcoded credentials | `${{ secrets.TOKEN }}` |
| No caching | `actions/cache@v4` for deps |
| Echo secrets | `::add-mask::$SECRET` |

## Patterns

```yaml
# Pattern 1: Standard workflow with best practices
name: CI
on:
  push:
    branches: [main]
    paths: ['src/**', '.github/workflows/*.yml']
  pull_request:
    branches: [main]

permissions:
  contents: read
  packages: write

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      
      - name: Cache dependencies
        uses: actions/cache@v4
        with:
          path: ~/.npm
          key: ${{ runner.os }}-node-${{ hashFiles('**/package-lock.json') }}
      
      - name: Build
        run: npm ci && npm run build

# Pattern 2: Docker multi-arch build
  docker:
    needs: build
    runs-on: ubuntu-latest
    steps:
      - uses: docker/setup-buildx-action@v3
      - uses: docker/build-push-action@v5
        with:
          platforms: linux/amd64,linux/arm64
          cache-from: type=gha
          cache-to: type=gha,mode=max

# Pattern 3: Matrix testing
  test:
    strategy:
      fail-fast: true
      matrix:
        node: [18, 20]
    steps:
      - run: npm test
```

## Commands

| Task | Command |
|------|---------|
| Validate workflow | `act -n` (dry run with act) |
| Test locally | `act push` (requires act installed) |
| Check syntax | `yamllint .github/workflows/` |
| View runs | `gh run list` |
| View logs | `gh run view {run-id} --log` |
