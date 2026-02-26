# Frontend React Patterns

Reusable code patterns for React, TypeScript, Zustand state management, and WebSocket clients.

## Pattern Files

| Pattern | Description | Usage |
|---------|-------------|-------|
| `component.tsx` | Functional component template | New components |
| `zustand_store.ts` | Zustand store with persistence | State management |
| `async_handler.tsx` | Async state capture pattern | Avoiding stale closures |
| `auth_aware.tsx` | Authentication-aware API calls | Protected resources |

## Usage

Patterns are referenced in SKILL.md and auto-suggested when relevant triggers are detected.

### Component Pattern
```tsx
const Card: FC<{ item: Item }> = ({ item }) => (
  <div key={item.id} className="p-4 border rounded">
    {item.name}
  </div>
);
```

### Zustand Store Pattern
```tsx
export const useStore = create<State>()(
  persist(
    (set) => ({
      items: [],
      addItem: (i) => set((s) => ({ items: [...s.items, i] }))
    }),
    { name: 'store-key' }
  )
);

// Using selector (prevents unnecessary re-renders)
const items = useStore((s) => s.items);
```

### Async State Capture Pattern (Critical)
```tsx
const handleSave = async () => {
  // ⚠️ CRITICAL: Capture state BEFORE async call
  const capturedParams = { ...localParams };
  
  await updateNode(nodeId, { data: { ...node.data, ...capturedParams }});
  await saveCurrentWorkflow();  // Persist to backend
};
```

### Auth-Aware API Call Pattern
```tsx
const fetchData = async () => {
  try {
    const response = await api.get('/resource');
    return response.data;
  } catch (error) {
    if (error.response?.status === 401) {
      logout();  // Redirect, don't show error page
      return;
    }
    throw error;
  }
};
```

### JSX Comment Pattern
```tsx
{/* ✅ Correct JSX comment */}
<div>
  {/* This is how to comment in JSX */}
</div>

// ❌ Wrong: This causes syntax errors in JSX
```

## Pattern Selection

| Task | Pattern |
|------|---------|
| New component | component.tsx |
| Global state | zustand_store.ts |
| Async operations | async_handler.tsx |
| API calls | auth_aware.tsx |
