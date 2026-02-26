---
name: frontend-react
description: Load when editing .tsx, .jsx files or working in components/, pages/, store/, hooks/. Provides React, TypeScript, Zustand state management, and WebSocket client patterns.
---

# Frontend React

## Merged Skills
- **state-management**: Zustand stores, selectors, subscriptions
- **internationalization**: i18n, translation, locale patterns
- **performance**: React.memo, useMemo, useCallback optimization
- **authentication**: Login flows, token storage, auth guards
- **websocket-realtime**: WebSocket client, reconnection, message handling

## ⚠️ Critical Gotchas

| Category | Pattern | Solution |
|----------|---------|----------|
| Auth | 401 errors | Call `logout()` from authStore, don't show page-level error |
| JSX | Comment syntax error | Use `{/* comment */}` not `//` |
| Hooks | Stale closures | Add all deps to useEffect dependency array |
| State | Settings lost on refresh | Use localStorage for persistent settings |
| Zustand | Memory leaks | Clean up selectors/subscriptions |
| Auth | Wrong storage key | Use `localStorage.getItem('nop-auth')` not `'token'` |
| Async | State stale in callback | Capture with `{ ...localState }` BEFORE async calls |
| ConfigPanel | Save lost | Call `saveCurrentWorkflow()` after `updateNode()` |

## Rules

| Rule | Pattern |
|------|---------|
| Keys in lists | Always `key={item.id}` |
| Dependency arrays | Include all dependencies |
| Async in effects | Use wrapper function, never async callback |
| State management | Zustand for global, useState for local |
| Auth handling | Redirect on 401, don't show error page |

## Avoid

| ❌ Bad | ✅ Good |
|--------|---------|
| Prop drilling | Context or Zustand |
| `useEffect(async () => ...)` | Wrapper function inside |
| Missing keys | `key={id}` |
| Page-level 401 UI | `logout()` redirect |
| `// comment` in JSX | `{/* comment */}` |

## Patterns

```tsx
// Pattern 1: Component with Zustand selector
const items = useStore((s) => s.items);
const Card: FC<{item: Item}> = ({ item }) => (
  <div key={item.id}>{item.name}</div>
);

// Pattern 2: Store with persistence
export const useStore = create<State>()(
  persist(
    (set) => ({
      items: [],
      addItem: (i) => set((s) => ({ items: [...s.items, i] }))
    }),
    { name: 'store-key' }
  )
);

// Pattern 3: Async state capture (CRITICAL)
const handleSave = async () => {
  const capturedParams = { ...localParams };  // Capture BEFORE async
  await updateNode(nodeId, { data: { ...node.data, ...capturedParams }});
  await saveCurrentWorkflow();  // Persist to backend
};

// Pattern 4: Execution visualization in BlockNode
const executionStatus = (data as any).executionStatus as NodeExecutionStatus;
const borderColor = executionStatus ? statusColors[executionStatus] : categoryColor;
const isExecuting = executionStatus === 'running';

// Pattern 5: Auth-aware API call
const fetchData = async () => {
  try {
    const response = await api.get('/resource');
    return response.data;
  } catch (error) {
    if (error.response?.status === 401) {
      logout();  // Redirect, don't show error
      return;
    }
    throw error;
  }
};
```

## Execution Visualization

| Status | Border Color | Effect |
|--------|-------------|--------|
| running | cyan | animate-pulse + glow |
| completed | green | static glow |
| failed | red | static glow |
| pending | gray | default |

## Commands

| Task | Command |
|------|---------|
| Start dev | `cd frontend && npm start` |
| Run tests | `cd frontend && npm test` |
| Build | `cd frontend && npm run build` |
| Type check | `cd frontend && npx tsc --noEmit` |
| Lint | `cd frontend && npm run lint` |
