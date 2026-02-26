---
name: testing
description: Load when editing test_*, *.test.*, or *_test.py files, or working with pytest/jest frameworks. Provides testing patterns for Python and TypeScript projects.
---

# Testing

## Merged Skills
- **pytest**: Python testing with async support
- **jest**: TypeScript/React component testing
- **e2e**: End-to-end integration testing

## ⚠️ Critical Gotchas

| Category | Pattern | Solution |
|----------|---------|----------|
| Async fixtures | Fixture not async | Use `@pytest.fixture` with `async def` |
| Over-mocking | Everything mocked | Only mock at service boundaries |
| Flaky tests | Random failures | Add `pytest.mark.flaky` or fix race condition |
| E2E timing | Tests fail intermittently | Use explicit waits, not `sleep()` |
| Shared state | Tests affect each other | Fresh setup each test, isolate state |
| Wrong level | Unit test for integration | Match test type to what you're testing |

## Rules

| Rule | Pattern |
|------|---------|
| Test behavior | Test what it does, not how |
| Isolate tests | No shared state between tests |
| Fast first | Run API/UI tests before E2E |
| Meaningful names | Describe expected behavior in test name |
| E2E confirms | Only run E2E after API+UI pass |
| Mock boundaries | Mock external services, not internal logic |

## Avoid

| ❌ Bad | ✅ Good |
|--------|---------|
| Testing implementation | Testing behavior |
| Shared state | Fresh setup each test |
| Mock everything | Mock boundaries only |
| E2E for unit logic | E2E for user flows |
| `time.sleep()` in E2E | Explicit waits |
| Generic test names | `test_create_script_returns_201` |

## Testing Hierarchy

| Level | Target | When | Command |
|-------|--------|------|---------|
| 1. API | Backend endpoints | After API changes | `pytest backend/tests/api/` |
| 2. UI | Components, pages | After frontend changes | `npm test` |
| 3. E2E | Full flow | Final confirmation | `pytest backend/tests/e2e/ -m e2e` |

## Patterns

```python
# Pattern 1: API test with async client
class TestScriptAPI:
    async def test_create_script_returns_201(self, client):
        response = await client.post("/api/scripts/", json={"name": "test"})
        assert response.status_code == 201
        assert response.json()["id"] is not None

    async def test_list_scripts_returns_all(self, client, sample_scripts):
        response = await client.get("/api/scripts/")
        assert len(response.json()) == len(sample_scripts)

# Pattern 2: Async fixture
@pytest.fixture
async def sample_scripts(db_session):
    scripts = [Script(name=f"script_{i}") for i in range(3)]
    db_session.add_all(scripts)
    await db_session.commit()
    return scripts
```

```tsx
// Pattern 3: React component test
it('renders script list correctly', () => {
  render(<ScriptList scripts={mockScripts} />);
  expect(screen.getAllByTestId('script-item')).toHaveLength(3);
});

it('calls onRun when run button clicked', () => {
  const onRun = jest.fn();
  render(<ScriptCard script={mockScript} onRun={onRun} />);
  fireEvent.click(screen.getByRole('button', { name: /run/i }));
  expect(onRun).toHaveBeenCalledWith(mockScript.id);
});
```

```python
# Pattern 4: E2E test with full flow
@pytest.mark.e2e
class TestScriptWorkflow:
    """Final confirmation: full user flow"""
    
    async def test_create_run_delete_script(self, e2e_client):
        # Create
        create_resp = await e2e_client.post("/api/scripts/", json={"name": "E2E Test"})
        script_id = create_resp.json()["id"]
        
        # Run
        run_resp = await e2e_client.post(f"/api/scripts/{script_id}/run")
        assert run_resp.json()["status"] == "completed"
        
        # Delete
        delete_resp = await e2e_client.delete(f"/api/scripts/{script_id}")
        assert delete_resp.status_code == 204
```

## Commands

| Task | Command |
|------|---------|
| API tests | `cd backend && pytest tests/api/ -v` |
| UI tests | `cd frontend && npm test` |
| E2E tests | `cd backend && pytest tests/e2e/ -v -m e2e` |
| All tests | `pytest && npm test && pytest -m e2e` |
| Single file | `pytest tests/test_specific.py -v` |
| With coverage | `pytest --cov=app tests/` |
