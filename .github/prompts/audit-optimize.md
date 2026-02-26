# Audit & Optimize Workflow

Audit, organize, and optimize any project component (documentation, skills, code, AKIS framework) to match templates and reduce redundancy.

**Trigger:** When any component is scattered, verbose, redundant, or doesn't follow standards. Applicable to docs, skills, code refactoring, or framework cleanup.

---

## Quick Reference

**One-liner invocations by component:**
```bash
# Documentation
"Audit and optimize documentation in docs/"

# Skills  
"Audit and optimize skills in .github/skills/"

# Instructions
"Audit and optimize .github/copilot-instructions.md"

# Knowledge
"Audit and optimize project_knowledge.json"

# Prompts
"Audit and optimize workflow prompts in .github/prompts/"

# AKIS Framework (all components)
"Audit and optimize AKIS framework"
```

**Process:** AUDIT → PLAN → MERGE & CONSOLIDATE → STANDARDIZE → INDEX → VERIFY → DOCUMENT → COMPLETE

---

## Component Configuration

**Set these variables based on your target component:**

### Documentation
```bash
TARGET_DIR="docs"
FILE_PATTERN="*.md"
TEMPLATE="feature-doc.md"  # or guide-doc.md
INDEX_FILE="docs/INDEX.md"
```

### Skills
```bash
TARGET_DIR=".github/skills"
FILE_PATTERN="*.md"
TEMPLATE="skill.md"
INDEX_FILE=".github/skills/INDEX.md"
```

### Instructions
```bash
TARGET_FILE=".github/copilot-instructions.md"
MAX_LINES=150
# No template - keep terse
```

### Knowledge
```bash
TARGET_FILE="project_knowledge.json"
FORMAT="JSONL"
# Line 1 = map
```

### Prompts
```bash
TARGET_DIR=".github/prompts"
FILE_PATTERN="*.md"
TEMPLATE="workflow-prompt.md"
INDEX_FILE=".github/prompts/README.md"
```

### Code
```bash
TARGET_DIR="backend/app"  # or frontend/src
FILE_PATTERN="*.py"  # or *.ts, *.tsx
# Component-specific patterns
```

---

## Template Reference Matrix

| Component | Template | Required Sections | Max Length |
|-----------|----------|-------------------|------------|
| Feature Doc | `feature-doc.md` | Features, Quick Start, Usage, Config, Troubleshooting, Related Docs | ~300 lines |
| Guide Doc | `guide-doc.md` | Prerequisites, Quick Start, Steps, Troubleshooting, Related Resources | ~400 lines |
| Skill | `skill.md` | When to Use, Avoid, Overview, Examples | <100 lines |
| Workflow Prompt | `workflow-prompt.md` | Phases, Success Criteria, Patterns, Anti-Patterns, Example, Integration | 300-600 lines |
| Instructions | None | Terse guidance only | <150 lines |
| Knowledge | None | JSONL format, line 1 = map | No limit |

---

## Phases

### 1. AUDIT - Component Discovery & Analysis

**Objective:** Inventory target component and assess current state

**Step 1: Identify Component Type**

Determine what you're auditing:
- [ ] Documentation (docs/)
- [ ] Skills (.github/skills/)
- [ ] Instructions (.github/copilot-instructions.md)
- [ ] Knowledge (project_knowledge.json)
- [ ] Prompts (.github/prompts/)
- [ ] Code (backend/, frontend/)
- [ ] AKIS Framework (multiple components)

**Step 2: Run Component-Specific Audit**

#### For Documentation:
```bash
find ${TARGET_DIR:-docs} -type f -name "*.md" | wc -l
find ${TARGET_DIR:-docs} -type f -name "*.md" | sort
python /tmp/doc_audit.py  # Check template compliance
```

#### For Skills:
```bash
find .github/skills -name "*.md" -not -name "INDEX.md" | wc -l

# Check template compliance (4 required sections)
for skill in .github/skills/*.md; do
  [ "$skill" = ".github/skills/INDEX.md" ] && continue
  echo "Checking $skill..."
  grep -q "## When to Use" "$skill" || echo "  ❌ Missing: When to Use"
  grep -q "## Avoid" "$skill" || echo "  ❌ Missing: Avoid"
  grep -q "## Overview" "$skill" || echo "  ❌ Missing: Overview"
  grep -q "## Examples" "$skill" || echo "  ❌ Missing: Examples"
  wc -l "$skill" | awk '$1 > 100 {print "  ⚠️  Too long: " $1 " lines (target <100)"}'
done
```

#### For Instructions:
```bash
wc -l .github/copilot-instructions.md
# Target: <150 lines
[ $(wc -l < .github/copilot-instructions.md) -gt 150 ] && \
  echo "⚠️ Instructions too long (>150 lines)"
```

#### For Knowledge:
```bash
wc -l project_knowledge.json
# Validate line 1 is map
head -1 project_knowledge.json | python3 -c "import sys, json; json.loads(sys.stdin.read())" && \
  echo "✅ Line 1 is valid map" || echo "❌ Line 1 is not valid JSON"
# Validate all lines
python3 -c "import json; [json.loads(line) for line in open('project_knowledge.json')]" && \
  echo "✅ All lines valid JSONL" || echo "❌ Invalid JSONL found"
```

#### For Prompts:
```bash
find .github/prompts -name "*.md" -not -name "README.md" | wc -l

# Check template compliance
for prompt in .github/prompts/*.md; do
  [ "$prompt" = ".github/prompts/README.md" ] && continue
  echo "Checking $prompt..."
  grep -q "## Phases" "$prompt" || echo "  ❌ Missing: Phases"
  grep -q "## Success Criteria" "$prompt" || echo "  ❌ Missing: Success Criteria"
  grep -q "## Anti-Patterns" "$prompt" || echo "  ❌ Missing: Anti-Patterns"
  grep -q "## Example Session" "$prompt" || echo "  ❌ Missing: Example Session"
done
```

#### For Code:
```bash
# Find duplicate function names
find ${TARGET_DIR:-backend} -name "*.py" -exec grep -h "^def " {} \; | \
  cut -d"(" -f1 | sort | uniq -c | sort -rn | awk '$1 > 1'

# Find long files (>500 lines)
find ${TARGET_DIR:-backend} -name "*.py" -exec wc -l {} \; | \
  awk '$1 > 500 {print $0}' | sort -rn
```

**Step 3: Analyze Current Organization**
**Step 3: Analyze Current Organization**
- Check directory structure matches component type
- Identify duplicate content across files
- Find verbose or redundant sections
- Note missing INDEX or navigation
- Check cross-references and links

**Step 4: Identify Gaps from Workflow Logs** (critical for completeness)

#### Documentation Gaps:
```bash
# Find features in logs but not in docs/features/
grep -rh "Implemented\|Created.*feature\|Added.*feature" log/workflow/*.md | \
  grep -v "^#" | sort | uniq > /tmp/implemented_features.txt
ls docs/features/*.md 2>/dev/null | xargs -n1 basename | sed 's/\.md//' | \
  sort > /tmp/existing_features.txt
comm -23 /tmp/implemented_features.txt /tmp/existing_features.txt | head -10
```

#### Skill Gaps:
```bash
# Find patterns used 3+ times but no skill file
grep -rh "pattern\|technique\|approach" log/workflow/*.md | \
  grep -v "^#" | tr '[:upper:]' '[:lower:]' | \
  sort | uniq -c | sort -rn | awk '$1 >= 3 {print $1, $2, $3, $4}'
  
# Compare with existing skills
echo "Existing skills:"
ls .github/skills/*.md 2>/dev/null | xargs -n1 basename | sed 's/\.md//'
```

#### Instruction Gaps:
```bash
# Find repeated decisions (3+ sessions)
grep -rh "always\|never\|prefer\|avoid\|must\|should" log/workflow/*.md | \
  grep -v "^#" | sort | uniq -c | sort -rn | awk '$1 >= 3 {print}'

# Check if already in instructions
grep -i "always\|never\|prefer\|avoid" .github/copilot-instructions.md
```

#### Knowledge Gaps:
```bash
# Find entities mentioned 5+ times but not tracked
grep -rh "Frontend\.\|Backend\.\|Docker\.\|Agent\." log/workflow/*.md | \
  grep -v "^#" | sort | uniq -c | sort -rn | awk '$1 >= 5 {print}'
  
# Check against project_knowledge.json
grep '"name":' project_knowledge.json | cut -d'"' -f4 | sort
```

**What to look for in logs:**
- **Missing docs**: Features/changes implemented without documentation
- **Missing skills**: Recurring patterns (3+ sessions) without skill files
- **Missing knowledge**: Entities/relations referenced but not tracked  
- **Missing instructions**: Repeated decisions that should be codified

**Step 5: Generate Compliance Report**
   ```bash
   python /tmp/doc_audit.py
   ```

**Output:** Compliance metrics (% following templates), file counts by category, list of issues

---

### 2. PLAN - Define Reorganization Strategy

**Objective:** Create action plan for standardization

**Steps:**
1. Group documents by theme:
   - **features/** - Feature documentation
   - **guides/** - Setup, deployment, configuration guides
   - **technical/** - API references, protocols, specs
   - **architecture/** - System design, ADRs
   - **design/** - UI/UX specifications
   - **development/** - Contributing, testing, roadmap
   - **analysis/** - Research, measurements, investigations
   - **archive/** - Historical/deprecated documentation

2. Identify optimization opportunities:
   - **Documents/Skills to merge** (same topic, redundant content, >50% overlap)
   - **Scattered components** to consolidate into single source
   - Verbose sections to condense (>500 lines, repetitive)
   - Missing template sections to add
   - Content to make more terse (paragraphs → bullets)

3. **Prioritize merging/consolidation**:
   - Map duplicate content: Which files cover same topic?
   - Identify canonical source: Which version is most complete/recent?
   - Plan archive strategy: Move old versions to archive/ with date stamp
   - Update cross-references: Note all docs that link to merged files

4. **Identify gaps to fill from workflow logs**:
   - Review `log/workflow/` for recent sessions (last 10-20)
   - **Documentation gaps**: Features implemented without docs
   - **Skill gaps**: Recurring patterns (3+ sessions) not captured as skills
   - **Code gaps**: Repeated refactorings that need standardization
   - **Knowledge gaps**: Entities/relations mentioned but not tracked
   - **Instruction gaps**: Decisions made repeatedly that should be codified
   
   Example gap analysis:
   ```bash
   # Find features mentioned in logs but missing from docs/features/
   grep -h "Implemented\|Added\|Created" log/workflow/*.md | grep -i feature
   
   # Find skills used >3 times but not in .github/skills/
   grep -h "pattern\|skill\|used" log/workflow/*.md | sort | uniq -c | sort -nr
   ```

5. Create checklist:
   - [ ] Audit complete with metrics
   - [ ] **Gaps identified from workflow logs**
   - [ ] **Merging/consolidation plan created**
   - [ ] **Duplicate content merged**
   - [ ] **Old versions archived**
   - [ ] **Missing docs/skills/knowledge created**
   - [ ] Feature docs standardized
   - [ ] Guide docs standardized  
   - [ ] Technical docs updated
   - [ ] INDEX.md created/updated
   - [ ] **All cross-references updated**
   - [ ] Template compliance verified

**Output:** Actionable checklist with prioritized items

---

### 3. STANDARDIZE - Apply Templates

**Objective:** Update documents to match templates

**Steps:**

#### 3.0 Merge & Consolidate (Priority Step)

**Before applying templates, consolidate duplicate content:**

1. **Identify merge candidates:**
   - Documents covering same topic (e.g., multiple deployment guides)
   - Skills with >50% overlapping content
   - Code modules with duplicate functions
   - Framework components with similar purposes

2. **Consolidation process:**
   ```bash
   # Example for documentation
   # 1. Identify best source (most complete/recent)
   # 2. Extract unique content from others
   # 3. Merge into single canonical document
   # 4. Archive old versions with datestamp
   
   mkdir -p docs/archive/deployment-docs-2026-01-05/
   mv docs/old-deploy-v1.md docs/archive/deployment-docs-2026-01-05/
   mv docs/old-deploy-v2.md docs/archive/deployment-docs-2026-01-05/
   # Keep only docs/DEPLOYMENT.md with merged content
   ```

3. **Update cross-references:**
   - Find all links to merged files: `grep -r "old-deploy" docs/`
   - Update to point to new canonical source
   - Add redirect notes in archived files

4. **Document consolidation:**
   - Note in INDEX.md: "Consolidated from: file1, file2, file3"
   - Keep archive notes for historical reference
   - Update changelog with merge details

**Example consolidations:**
- 7 agent docs → `features/AGENTS_C2.md`
- 4 deployment docs → `guides/DEPLOYMENT.md`
- Multiple overlapping skills → single comprehensive skill

#### 3.1 Feature Documentation
Template: `.github/templates/feature-doc.md`

Required sections:
```markdown
# Feature Name
{One-line description}

## Features
- ✅ Feature 1
- ✅ Feature 2

## Quick Start
```bash
{minimal code}
```

## Usage
### {Use Case}
```{language}
{example}
```

## Configuration
| Option | Default | Description |
|--------|---------|-------------|

## Troubleshooting
**Problem**: {Issue}
**Solution**: {Fix}

## Related Documentation
- [Link](path.md) - Description

---
**Document Version**: 1.0
**Last Updated**: YYYY-MM-DD
**Status**: Production Ready
```

#### 3.2 Guide Documentation
Template: `.github/templates/guide-doc.md`

Required sections:
```markdown
# Guide Title
{One-line description}

## Prerequisites
- Requirement 1
- Requirement 2

## Quick Start
```bash
{commands}
```

## Steps
### 1. {Step Title}
```bash
{command}
```

## Troubleshooting
### {Issue}
**Problem**: {Description}
**Solution**: {Fix}

## Related Resources
- [Link](path.md) - Description

---
**Document Version**: 1.0
**Last Updated**: YYYY-MM-DD
**Status**: Production Ready
```

#### 3.3 Content Optimization
- Replace verbose paragraphs with bullet points
- Convert walls of text into tables or code blocks
- Remove redundant explanations
- Add Quick Start sections for immediate value
- Include practical examples
- Target 60-70% reduction in verbosity

**Output:** All core documents following templates with version footers

---

### 4. INDEX - Create Comprehensive Navigation

**Objective:** Build master index for easy discovery

**Steps:**
1. Create `docs/INDEX.md` with structure:
   ```markdown
   # {Project} Documentation Index
   
   ## 📍 Navigation
   | Category | Description | Location |
   
   ## Quick Start
   | Document | Purpose | Audience |
   
   ## {Category}
   ### [DOC.md](path/DOC.md)
   **Description**
   - Topic 1
   - Topic 2
   **Audience**: {Who}
   
   ## Changelog
   ### YYYY-MM-DD (vX.Y) - Description
   - Change 1
   - Change 2
   ```

2. Include for each document:
   - Title and path
   - One-line description
   - Key topics covered
   - Target audience
   - Note if consolidated from multiple sources

3. Add navigation aids:
   - Quick Start section for common tasks
   - By-role navigation (Developers, DevOps, Users)
   - By-topic navigation
   - File counts per category

4. Maintain changelog:
   - Track major reorganizations
   - Note consolidations and archives
   - Document version changes

**Output:** Comprehensive INDEX.md (300-500 lines) with full navigation

---

### 5. VERIFY - Quality Assurance

**Objective:** Ensure all changes are correct and consistent

**Checks:**
```bash
# Re-run compliance audit
python /tmp/doc_audit.py

# Verify all links work
find docs -name "*.md" -exec grep -h "\[.*\](" {} \; | grep -o "(.*\.md" | sort -u

# Check for broken references
grep -r "docs/" docs/ | grep -v "Binary" | grep "\.md:" | grep -v "^docs/INDEX.md"

# Validate template sections present
grep -l "## Features" docs/features/*.md
grep -l "## Quick Start" docs/guides/*.md
grep -l "Document Version" docs/**/*.md
```

**Validation criteria:**
- [ ] Template compliance >80% for core docs
- [ ] All documents have version footers
- [ ] INDEX.md includes all non-archived docs
- [ ] No broken internal links
- [ ] Consistent formatting (bullets, code blocks, tables)
- [ ] Content is scannable and terse

**Output:** Validated documentation ready for commit

---

### 6. DOCUMENT - Create Workflow Log

**Objective:** Record the standardization work

**Steps:**
1. Create workflow log: `log/workflow/YYYY-MM-DD_HHMMSS_documentation-standardization.md`

2. Include metrics:
   ```markdown
   # Documentation Standardization
   
   **Date**: YYYY-MM-DD HH:MM
   **Duration**: ~X minutes
   
   ## Summary
   Audited and standardized all documentation to match AKIS templates.
   
   ## Changes
   - Standardized: N feature docs, M guide docs
   - Created: INDEX.md with comprehensive navigation
   - Condensed: X lines → Y lines (Z% reduction)
   - Compliance: A% → B%
   
   ## Files Modified
   - docs/features/*.md - Added template sections
   - docs/guides/*.md - Restructured with Steps sections
   - docs/INDEX.md - Created master index
   
   ## Verification
   - [x] Template compliance >80%
   - [x] All links verified
   - [x] INDEX.md complete
   ```

**Output:** Documented standardization session

---

### 7. COMPLETE - Finalize Changes

**Objective:** Commit all changes with clear message

**Steps:**
1. Review all modified files:
   ```bash
   git status
   git diff --stat
   ```

2. Commit with descriptive message:
   ```
   docs: standardize documentation to AKIS templates
   
   - Audited 72 markdown files across docs/
   - Standardized 8 core documents to match templates
   - Created comprehensive INDEX.md (418 lines)
   - Reduced content verbosity by 65% (865→300 lines)
   - Improved template compliance from 17.9% to 80%
   ```

3. Update knowledge:
   ```json
   {"type":"entity","name":"Documentation","observations":["Standardized to templates","Compliance 17.9%→80%","upd:YYYY-MM-DD"]}
   ```

**Output:** Clean commit with all documentation improvements

---

## Success Criteria

### Universal (All Components):
✅ All components inventoried and categorized by theme
✅ **Workflow logs reviewed for gaps** (missing docs/skills/knowledge/instructions)
✅ **Gaps identified and filled** from recent sessions
✅ **Duplicate/redundant content identified and merged**
✅ **Old versions archived with datestamps**
✅ **No broken internal links after merging**
✅ **Cross-references updated to canonical sources**
✅ Consistent formatting throughout

### Component-Specific Validation:

**For Documentation:**
✅ Template compliance >80% for core docs
✅ Comprehensive INDEX.md with navigation and summaries
✅ Content reduced by 60-70% while maintaining clarity
✅ All documents have version footers (vX.Y | YYYY-MM-DD | Status)
✅ Quick Start sections for practical value

**For Skills:**
✅ All skills follow `skill.md` template (4 required sections: When to Use, Avoid, Overview, Examples)
✅ Each skill <100 lines
✅ Patterns from 3+ sessions captured as skills
✅ INDEX.md categorizes all skills by type
✅ No overlapping skills (>50% content overlap)

**For Instructions:**
✅ Length <150 lines total
✅ No redundant guidance (consolidated or removed)
✅ Repeated decisions (3+ sessions) codified
✅ Skills referenced instead of duplicating patterns
✅ Clear, actionable guidance only

**For Knowledge:**
✅ Line 1 is valid JSON map
✅ All lines valid JSONL format
✅ Entities from 5+ sessions tracked
✅ Relations between entities defined
✅ Stale entities (<20 sessions) reviewed/archived

**For Prompts:**
✅ All prompts follow `workflow-prompt.md` template
✅ Required sections present (Phases, Success Criteria, Anti-Patterns, Example, Integration)
✅ README.md updated with new prompts
✅ Each prompt 300-600 lines (comprehensive but not verbose)

**For Code:**
✅ No duplicate functions across modules
✅ All files <500 lines
✅ Type hints present (Python/TypeScript)
✅ Consistent patterns across codebase

---

## Consolidation & Merging Patterns

### Pattern: Duplicate Documentation/Skills
**Symptom:** Multiple files/components covering same topic or functionality
**Action:** 
1. Identify best canonical source (most complete, recent, well-structured)
2. Extract unique content from duplicates
3. Merge into single authoritative source
4. Archive old versions: `component-archive-YYYY-MM-DD/`
5. Update all cross-references
6. Note consolidation in INDEX/changelog

**Example:** 7 agent docs → `features/AGENTS_C2.md` (consolidated with archive)

### Pattern: Overlapping Skills/Code
**Symptom:** Similar patterns/functions with >50% overlap
**Action:**
1. Compare content/functionality side-by-side
2. Merge into comprehensive version with all patterns
3. Remove redundant files
4. Update references in instructions/imports

**Example:** `frontend-components.md` + `ui-patterns.md` → `frontend-react.md`

### Pattern: Scattered Documentation
**Symptom:** Multiple docs covering same topic
**Action:** Consolidate into single source, archive old versions
**Example:** 7 agent docs → features/AGENTS_C2.md

### Pattern: Missing Documentation/Skills/Knowledge (Gap from Workflow Logs)
**Symptom:** Work completed in sessions but not captured in docs/skills/knowledge
**Action:**
1. Review recent workflow logs: `ls -t log/workflow/*.md | head -20`
2. **For missing docs**: Create feature/guide doc for implemented work
3. **For missing skills**: Extract recurring pattern (3+ sessions) into skill file
4. **For missing knowledge**: Add entities/relations to project_knowledge.json
5. **For missing instructions**: Codify repeated decisions into framework instructions
6. Document source: "Based on sessions: log/workflow/YYYY-MM-DD_*.md"

**What to look for:**
- Features implemented without documentation
- Patterns used 3+ times without skill files
- Entities referenced but not in knowledge base
- Decisions repeated without codified guidance

**Example:** Agent C2 feature implemented across 5 sessions → created `features/AGENTS_C2.md`

### Pattern: Verbose Feature Documentation
**Symptom:** Feature docs >400 lines with detailed explanations
**Action:** Extract key points, use bullets, add Quick Start
**Example:** IMPLEMENTED_FEATURES: 471→180 lines (62% reduction)

### Pattern: Missing Templates
**Symptom:** Documents without standard sections
**Action:** Add Features, Quick Start, Usage, Troubleshooting sections
**Example:** STORM_FEATURE: 40%→100% compliance

### Pattern: No Navigation
**Symptom:** No master index or table of contents
**Action:** Create INDEX.md with categories and summaries
**Example:** Created 418-line INDEX with full navigation

### Pattern: Inconsistent Formatting
**Symptom:** Mix of paragraphs, lists, tables without structure
**Action:** Standardize to bullets for features, tables for config, code blocks for examples
**Example:** All feature docs now use consistent formatting

---

## Anti-Patterns to Avoid

❌ **Merging without archiving:** Don't delete old versions permanently
✅ Archive with datestamp: `archive/component-YYYY-MM-DD/`

❌ **Losing unique content:** Don't merge without extracting all valuable info
✅ Review each file, extract unique sections before merging

❌ **Over-condensing:** Don't remove essential information
✅ Keep key details, remove only redundancy

❌ **Breaking links:** Don't move/merge files without updating references
✅ Update INDEX.md and all cross-references, add redirect notes

❌ **Template rigidity:** Don't force templates where inappropriate
✅ Adapt templates for different document types (catalog vs feature)

❌ **Ignoring existing structure:** Don't reorganize well-organized components
✅ Focus on problematic areas, leave good organization alone

❌ **No version tracking:** Don't update without version footers
✅ Always add version, date, and status to documents

❌ **Silent consolidation:** Don't merge without documenting what was merged
✅ Note in INDEX: "Consolidated from: file1, file2, file3"

❌ **Ignoring workflow logs:** Don't skip gap analysis from recent sessions
✅ Review workflow logs to identify missing docs/skills/knowledge/instructions

---

## Example Session

### Input
- 72 markdown files in docs/ folder
- 20 recent workflow logs in log/workflow/
- No master index
- Template compliance: 17.9%
- Verbose documents (471+ lines)
- Request: "Organize and optimize documentation"

### Actions Taken
1. Audited all 72 files with compliance script
2. **Reviewed 20 workflow logs** to identify gaps
3. **Found gaps**: Agent C2 feature in 5 sessions but no doc, Docker patterns in 8 sessions but no skill
4. Organized into 8 thematic categories
5. Standardized 5 feature docs (AGENTS_C2, STORM, FILTERING, etc.)
6. **Created missing AGENTS_C2.md** based on workflow logs
7. **Created docker-hot-reload.md skill** from repeated patterns
8. Standardized 3 guide docs (QUICK_START, DEPLOYMENT, CONFIGURATION)
9. Created comprehensive INDEX.md (418 lines)
10. Condensed IMPLEMENTED_FEATURES: 471→180 lines
11. Condensed FEATURE_PROPOSALS: 394→120 lines
12. Added version footers to all docs
13. Verified all links and template compliance

### Outcome
- Template compliance: 17.9% → 80%
- Content reduction: 865 → 300 lines (65%)
- **Gaps filled**: 1 feature doc, 1 skill created from logs
- Created master INDEX with full navigation
- All core docs follow templates
- Easy discovery with thematic organization

---

## Integration with AKIS

This workflow is a **documentation maintenance task** separate from regular development sessions:

```
Regular Session:
CONTEXT → PLAN → IMPLEMENT → VERIFY → LEARN → COMPLETE

Documentation Standardization (this workflow):
AUDIT → PLAN → STANDARDIZE → INDEX → VERIFY → DOCUMENT → COMPLETE
```

**Frequency:** 
- After major releases
- When onboarding new contributors
- Every 6-12 months for maintenance
- When documentation becomes scattered or verbose

**Trigger:** 
- User request for documentation organization
- Template compliance <50%
- No master index exists
- Documents scattered across multiple locations

**Purpose:** Standardize documentation structure, improve discoverability, reduce verbosity, ensure template compliance

**Key Principle:** *Terse and Effective* - Remove redundancy, add structure, maintain clarity

---

## Related Files

- **Templates:** `.github/templates/feature-doc.md`, `.github/templates/guide-doc.md`
- **Index:** `docs/INDEX.md`
- **Workflow Logs:** `log/workflow/*-documentation-standardization.md`
- **Knowledge:** `project_knowledge.json`

---

## Reusability

This workflow is **universal** and can be applied to:

**Documentation**: Organize docs, create INDEX, standardize to templates
**Skills**: Consolidate overlapping skills, remove unused, standardize format
**Code**: Refactor for consistency, reduce duplication, improve structure
**AKIS Framework**: Streamline instructions, optimize workflows, clean scripts

The core process (AUDIT → PLAN → STANDARDIZE → INDEX → VERIFY) adapts to any component while maintaining the same methodology.

---

## Applicability

Use this workflow for:
- 📄 **Documentation**: Scattered docs, verbose content, no index
- 🛠️ **Skills**: Overlapping skills, unused patterns, inconsistent format
- 💻 **Code**: Duplication, inconsistent patterns, refactoring needs
- ⚙️ **AKIS Framework**: Verbose instructions, scattered scripts, framework cleanup

Adapt the phases and steps to your specific target while keeping the core methodology.

---

*This prompt was created from documentation standardization work on 2026-01-05 and is subject to improvement.*
