# AKIS Framework v8.0

**Adaptive Knowledge Intelligence System** for development standardization.

## Structure

### .github/ (Version Control & CI/CD)
- `agents/` - AI agent definitions (*.agent.md)
- `skills/` - Reusable skill modules with INDEX.md
- `workflows/` - GitHub Actions CI/CD
- `templates/` - Project templates
- `prompts/` - Standard prompts
- `instructions/` - Development instructions
- `scripts/` - AKIS maintenance automation

### .claude/ (Claude Code Config)
- `settings.json` - Permissions, env vars, model config

### .project/ (Project Management)
- `agents/` - Project-specific agent overrides
- `blueprints/` - Design documents (created BEFORE code)
- `proposals/` - Feature proposals
- `skills/` - Project-specific skills
- `automation-flows/` - Workflow automation

### project_knowledge.json
Knowledge graph with:
- `hot_cache` - Top 30 entities for instant context
- `domain_index` - Per-domain entity lookup
- `gotchas` - Historical issues + solutions
- `interconnections` - Entity dependency chains

## Usage

### VSCode
Standard VSCode workflow with GitHub Copilot.

### Claude Code
Loads AKIS from `.github/agents/` and `.claude/settings.json`.

### OpenClaw
Can invoke agents via `.github/agents/*.agent.md` definitions.

## Standards

1. **Design before code** - Blueprints in `.project/blueprints/`
2. **Max 7 components** - Cognitive limit compliance
3. **Document gotchas** - Update `project_knowledge.json`
4. **Test coverage** - Required for CI/CD
5. **Agent trace** - All agents return structured output
