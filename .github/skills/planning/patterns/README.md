# Planning Patterns

Reusable patterns for feature planning and architecture decisions.

## Pattern Files

| Pattern | Description | Usage |
|---------|-------------|-------|
| `blueprint.md` | Feature blueprint | New feature design |
| `scope_definition.md` | Scope boundaries | Define IN/OUT |
| `task_decomposition.md` | Task breakdown | Split into <3 files |
| `handoff_template.md` | Agent handoff | planning → code |

## Blueprint Template
```markdown
# Blueprint: {Feature Name}

## Scope
- **Goal:** One sentence describing outcome
- **IN:** What this feature includes
- **OUT:** What this feature excludes
- **Files:** Estimated file count and locations

## Design
- **Approach:** High-level solution strategy
- **Components:** Key parts and their responsibilities
- **Dependencies:** External services, libraries, other features

## Tasks
1. [ ] Task description [backend-api]
2. [ ] Task description [frontend-react]
3. [ ] Task description [testing]

## Research Notes
- {Finding 1}
- {Finding 2}
```

## Scope Definition
```markdown
## Scope: {Feature}

### IN (Included)
- Requirement 1
- Requirement 2

### OUT (Excluded)
- Future enhancement
- Related but separate work

### Boundaries
- Maximum file count: N
- Skills required: [list]
```

## Task Decomposition
```markdown
## Tasks for {Feature}

### Phase 1: Setup
- [ ] Task 1.1 [skill] (1 file)
- [ ] Task 1.2 [skill] (2 files)

### Phase 2: Implementation
- [ ] Task 2.1 [skill] (2 files)

### Phase 3: Verification
- [ ] Task 3.1 [testing] (1 file)
```

## Pattern Selection

| Stage | Pattern |
|-------|---------|
| Initial design | blueprint.md |
| Define boundaries | scope_definition.md |
| Break down work | task_decomposition.md |
| Delegate to agent | handoff_template.md |
