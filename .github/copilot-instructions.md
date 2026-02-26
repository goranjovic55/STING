# AKIS v8.0

> 100k simulation: 57.1% → 95.6% success rate (+38.5%), 93.0% gate compliance
> Industry patterns: CI, GitHub Flow, TDD, Conventional Commits, 12-Factor, Agile

## Gates
| G | Check | Fix | Cost | Industry Pattern |
|---|-------|-----|------|------------------|
| 0 | No knowledge | Load **knowledge** skill → `head -100 project_knowledge.json` ONCE | +13k tokens | 12-Factor: Config first |
| 1 | No ◆ | `manage_todo_list` → mark ◆ | Lost tracking | Conventional Commits |
| 2 | ⚠️ No skill | Load skill FIRST (**VISUAL WARNING**) | +5.2k tokens | TDD: Test/skill first |
| 3 | No START | Do START with announcement | Lost context | GitHub Flow: Branch |
| 4 | ⚠️ No END | Do END (**BLOCK COMMIT** >15 min) | Lost trace | CI: Commit/merge |
| 5 | ⚠️ No verify | Syntax check AFTER EVERY edit | +8.5 min | CI: Self-testing |
| 6 | Multi ◆ | One only | Confusion | Trunk-Based: Short |
| 7 | ⚠️ No parallel | Use pairs for 5+ (60% target) | +14 min | Agile: Pair programming |

## START
1. Load **knowledge** skill → `head -100 project_knowledge.json` → IN MEMORY: hot_cache, domain_index, gotchas
2. Load **session** skill → Read `skills/INDEX.md` → pre-load: frontend-react ⭐ + backend-api ⭐
3. `manage_todo_list` → structured TODO naming: `○ [agent:phase:skill] Task`
4. **Announce:** `AKIS v8.0 [complexity]. Skills: [list]. [N] tasks. Ready.`

## TODO Format
`○ [agent:phase:skill] Task [context]`

| Field | Values |
|-------|--------|
| agent | AKIS, code, architect, debugger, reviewer, documentation, research, devops |
| phase | START, WORK, END, VERIFY |
| skill | backend-api, frontend-react, docker, testing, debugging, documentation, knowledge, session |
| context | `parent→X` `deps→Y,Z` |

## WORK
**Use knowledge skill first:** domain_index → paths, gotchas → bugs, hot_cache → entities

| Trigger | Skill | MANDATORY |
|---------|-------|-----------|
| architecture, structure, "where is" | knowledge | ✅ BEFORE LOOKUP |
| .tsx .jsx | frontend-react | ✅ BEFORE ANY EDIT |
| .py backend/ | backend-api | ✅ BEFORE ANY EDIT |
| Dockerfile | docker | ✅ BEFORE ANY EDIT |
| error | debugging | ✅ BEFORE ANY EDIT |
| test_* | testing | ✅ BEFORE ANY EDIT |
| .md docs/ | documentation | ✅ BEFORE ANY EDIT |

**Flow:** ◆ → **Load Skill (G2)** → Edit → **Verify (G5)** → ✓

⚠️ **G2 VIOLATION = +5,200 tokens waste**. Load skill BEFORE first edit, not after.

## END
**Trigger:** Session >15 min OR when you see "done", "complete", "finished"

1. Close ⊘, verify all edits (use **session** skill)
2. **Create `log/workflow/YYYY-MM-DD_HHMMSS_task.md`** (G4 - MANDATORY)
3. Run scripts with `--update` (auto-backup), present table with changes
4. **ASK before git push**

⚠️ **G4 VIOLATION = Lost traceability**. Workflow log REQUIRED for sessions >15 min.
⚠️ **Rollback:** Backups in `.github/*/.backups/` - use `cp` to restore.

## Delegation (Simplified Binary Decision)
| File Count | Action | Efficiency |
|------------|--------|------------|
| <3 files | Optional (AKIS direct) | 0.594 |
| 3+ files | **runSubagent** (MANDATORY) | 0.789 (+33%) |

**Agent Selection:**
| Task Type | Agent | Success Rate |
|-----------|-------|--------------|
| design, blueprint | architect | 97.7% |
| code changes | code | 93.6% |
| bug fix, error | debugger | 97.3% |
| docs, readme | documentation | 89.2% |
| research, standards | research | 76.6% |

**Delegation saves:** 10.9 min average, +8% quality improvement

## Context Isolation (Clean Handoffs)
| Phase | Handoff |
|-------|---------|
| planning → code | Artifact only |
| research → design | Summary + decisions |
| code → review | Code changes only |

**Rule:** Produce typed artifact, not conversation history. -48.5% tokens.

## Parallel (G7: 60% TARGET)
**Current:** 19.1% parallel rate. **Goal:** 60%+

| Pair | Pattern | Time Saved |
|------|---------|------------|
| code + docs | ✅ Parallel | 8.5 min |
| code + tests | ✅ Parallel | 12.3 min |
| debugger + docs | ✅ Parallel | 6.2 min |
| research + code | ❌ Sequential | - |
| frontend + backend | ❌ Sequential (API contract) | - |

**Decision:** Independent tasks = Parallel. Same files or dependencies = Sequential.

⚠️ **G7 GAP = -294k minutes** across 100k sessions. Use runSubagent for parallel work.

## Symbols
✓ done | ◆ working | ○ pending | ⊘ paused | ⧖ delegated

## Session Types (Industry Patterns)
| Type | % | Skill Focus | Commit Type |
|------|---|-------------|-------------|
| Feature Development | 35% | frontend-react, backend-api | feat: |
| Bug Fix | 25% | debugging, testing | fix: |
| Code Review | 15% | security | - |
| Refactoring | 10% | backend-api, frontend-react | refactor: |
| Testing | 10% | testing | test: |
| Documentation | 5% | documentation | docs: |

**Auto-detect from workflow:** feat(scope), fix(scope), docs(scope), refactor(scope), test(scope)

## Gotchas
| Issue | Fix | Gate |
|-------|-----|------|
| Edit without skill | Load skill FIRST (30.8% violation) | G2 |
| Skip workflow log | Create log for >15 min sessions (21.8% violation) | G4 |
| Skip verification | Verify syntax after EVERY edit (18.0% violation) | G5 |
| Skip parallel | Use parallel pairs for 6+ tasks (target 60%) | G7 |
| Query knowledge repeatedly | Read 100 lines ONCE | G0 |
| Text TODOs | Use `manage_todo_list` | G1 |
| Skip announcement | Announce before WORK | G3 |
| Multiple ◆ | One only | G6 |
| Auto-push | ASK first | END |
| Skip delegation for 3+ files | Use runSubagent (MANDATORY) | Delegation |
