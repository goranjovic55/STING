# AKIS Workflow Prompts

Specialized multi-phase workflows for complex tasks.

**Regular Work:** Free-form, context-driven, query resources when stuck
**Workflow Prompts:** Prescribed phases (CONTEXT → ANALYZE → ...), step-by-step

## Available

### akis-workflow-analyzer.md

**Purpose:** Analyze sessions to identify patterns and propose improvements

**Trigger:**
- Auto: Every 10 sessions (check via `session_tracker.py`)
- Manual: Anytime

**Phases:** CONTEXT → ANALYZE → REVIEW → IMPLEMENT → VERIFY → DOCUMENT → COMPLETE

**Actions:**
1. Analyze workflow logs
2. Identify patterns
3. Suggest skills/docs updates
4. Propose improvements
5. Update knowledge base

**Usage:**
```bash
python .github/scripts/session_tracker.py check-maintenance
# If due, follow akis-workflow-analyzer.md
```

## Creating New Prompts

1. Use template: `templates/workflow-prompt.md`
2. Define phases with objectives, steps, outputs
3. Include examples and commands
   - When to trigger (auto/manual)
   - What purpose it serves

5. **Update this README:** Add entry for the new prompt

## When to Create a Workflow Prompt vs Regular Work

**Create a Workflow Prompt if:**
- ✅ Task repeats regularly (e.g., every N sessions)
- ✅ Multiple distinct phases with dependencies
- ✅ Benefits from standardized procedure
- ✅ Used by multiple people or sessions

**Use Regular Free-form Work if:**
- ✅ One-off implementation task
- ✅ Context-specific problem solving
- ✅ Natural discovery process
- ✅ Most feature development

## Templates

- **Workflow Prompt:** `.github/templates/workflow-prompt.md`
- **Skill (for free-form patterns):** `.github/templates/skill.md`

## Relationship to AKIS Framework

Workflow prompts are **independent specialized workflows** that complement free-form work:

**Regular Session Flow:**
```
Session Start (auto context) → Work Freely → Session End (required checklist)
```
- Query knowledge/docs/skills as needed
- No prescribed phases
- Natural problem-solving

**Workflow Prompt Flow:**
```
CONTEXT → ANALYZE → REVIEW → IMPLEMENT → VERIFY → DOCUMENT → COMPLETE
```
- Prescribed step-by-step phases
- Triggered automatically or manually
- Specialized, repeatable procedures

Both approaches are part of AKIS, used for different purposes.
- Standardizes patterns across sessions
- Organizes and cleans documentation
- Adjusts framework instructions
- Triggered automatically every 10 sessions or manually
- Uses session tracking (`.github/scripts/session_tracker.py`)

The prompts in this folder operate at a higher level, analyzing multiple sessions to improve the framework itself. They are triggered in COMPLETE phase when maintenance is due, NOT during the regular LEARN phase.

## Standards

- **Format**: Markdown with clear phase headings
- **Length**: Comprehensive but scannable (use headings and lists)
- **Actionable**: Each phase should have concrete steps
- **Examples**: Include example sessions and outputs
- **Integration**: Reference related scripts and skills

## Related Files

- **Instructions**: `.github/copilot-instructions.md` (main AKIS instructions)
- **Skills**: `.github/skills/` (reusable patterns)
- **Scripts**: `.github/scripts/` (automation tools)
- **Templates**: `.github/templates/` (workflow log templates)
- **Logs**: `log/workflow/` (session history)

---

*These prompts enable the AKIS framework to improve itself based on actual usage patterns.*
