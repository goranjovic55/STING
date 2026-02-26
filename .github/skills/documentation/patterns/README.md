# Documentation Patterns

Reusable patterns for README, API docs, and technical documentation.

## Pattern Files

| Pattern | Description | Usage |
|---------|-------------|-------|
| `readme_template.md` | README structure | Project documentation |
| `api_doc.md` | API documentation | Endpoint reference |
| `changelog_entry.md` | Changelog format | Version history |
| `architecture_doc.md` | Architecture docs | System design |

## README Template
```markdown
# Project Name

> Brief description

## Quick Start
1. Install dependencies
2. Configure environment
3. Run the application

## Features
- Feature 1
- Feature 2

## Documentation
- [API Reference](docs/api.md)
- [Architecture](docs/architecture.md)
```

## API Documentation
```markdown
## Endpoint: GET /api/items/{id}

### Description
Retrieves a single item by ID.

### Parameters
| Name | Type | Required | Description |
|------|------|----------|-------------|
| id | int | Yes | Item identifier |

### Response
```json
{
  "id": 1,
  "name": "Item Name",
  "created_at": "2024-01-01T00:00:00Z"
}
```

### Error Codes
| Code | Description |
|------|-------------|
| 404 | Item not found |
| 401 | Unauthorized |
```

## Changelog Entry
```markdown
## [1.2.0] - 2024-01-15

### Added
- New feature X

### Fixed
- Bug in component Y

### Changed
- Updated dependency Z
```

## Pattern Selection

| Doc Type | Pattern |
|----------|---------|
| Project README | readme_template.md |
| API reference | api_doc.md |
| Release notes | changelog_entry.md |
| System design | architecture_doc.md |
