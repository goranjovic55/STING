# CI/CD Patterns

Reusable patterns for GitHub Actions and deployment workflows.

## Pattern Files

| Pattern | Description | Usage |
|---------|-------------|-------|
| `build_workflow.yml` | Build pipeline | Code compilation |
| `test_workflow.yml` | Test pipeline | Automated testing |
| `deploy_workflow.yml` | Deploy pipeline | Production deployment |
| `pr_checks.yml` | PR validation | Pre-merge checks |

## Build Workflow
```yaml
name: Build
on: [push, pull_request]
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: '3.11'
      - run: pip install -r requirements.txt
      - run: python -m pytest --cov
```

## Test Workflow
```yaml
name: Test
on: [push, pull_request]
jobs:
  test:
    runs-on: ubuntu-latest
    services:
      postgres:
        image: postgres:15
        env:
          POSTGRES_PASSWORD: test
    steps:
      - uses: actions/checkout@v4
      - run: pip install -r requirements.txt
      - run: pytest -v
```

## Deploy Workflow
```yaml
name: Deploy
on:
  push:
    branches: [main]
jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: docker build -t app .
      - run: docker push ${{ secrets.REGISTRY }}/app
```

## PR Checks
```yaml
name: PR Checks
on: [pull_request]
jobs:
  lint:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: npm run lint
      - run: npm run type-check
```

## Pattern Selection

| Task | Pattern |
|------|---------|
| Build code | build_workflow.yml |
| Run tests | test_workflow.yml |
| Deploy to prod | deploy_workflow.yml |
| PR validation | pr_checks.yml |
