# Testing Patterns

Reusable patterns for pytest, jest, and end-to-end testing.

## Pattern Files

| Pattern | Description | Usage |
|---------|-------------|-------|
| `api_test.py` | API test template | Backend endpoint tests |
| `async_fixture.py` | Async fixture template | Database setup |
| `component_test.tsx` | React component test | Frontend unit tests |
| `e2e_test.py` | E2E test template | Full user flow tests |

## API Test with Async Client
```python
class TestScriptAPI:
    async def test_create_script_returns_201(self, client):
        response = await client.post("/api/scripts/", json={"name": "test"})
        assert response.status_code == 201
        assert response.json()["id"] is not None

    async def test_list_scripts_returns_all(self, client, sample_scripts):
        response = await client.get("/api/scripts/")
        assert len(response.json()) == len(sample_scripts)
```

## Async Fixture
```python
@pytest.fixture
async def sample_scripts(db_session):
    scripts = [Script(name=f"script_{i}") for i in range(3)]
    db_session.add_all(scripts)
    await db_session.commit()
    return scripts
```

## React Component Test
```tsx
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

## E2E Test with Full Flow
```python
@pytest.mark.e2e
class TestScriptWorkflow:
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

## Pattern Selection

| Test Type | Pattern |
|-----------|---------|
| API endpoint | api_test.py |
| Database setup | async_fixture.py |
| React component | component_test.tsx |
| Full user flow | e2e_test.py |
