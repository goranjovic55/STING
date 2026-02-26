#!/usr/bin/env python3
"""
Workflow Log Parser v2.0

Parses structured YAML front matter from workflow logs.
Falls back to legacy keyword matching for older logs.
"""

import re
import yaml
from pathlib import Path
from dataclasses import dataclass, field
from typing import Dict, List, Any, Optional
from collections import defaultdict


@dataclass
class FileChange:
    """Represents a file modification."""
    path: str
    type: str
    domain: str
    changes: str = ""


@dataclass
class ErrorInfo:
    """Represents an error encountered."""
    type: str
    message: str
    file: str = ""
    line: int = 0
    fixed: bool = False
    root_cause: str = ""
    skill_used: str = ""


@dataclass
class RootCause:
    """Represents a problem→solution pattern."""
    problem: str
    solution: str
    category: str = "bug"
    skill: str = ""


@dataclass
class AgentDelegation:
    """Represents a delegated agent task."""
    name: str
    task: str
    result: str = "success"
    duration_minutes: int = 0


@dataclass
class CommandExecution:
    """Represents a command run during session."""
    cmd: str
    domain: str
    success: bool = True
    output_summary: str = ""
    error: str = ""


@dataclass 
class SkillTrigger:
    """Represents what triggered a skill load."""
    skill: str
    trigger: str


@dataclass
class GateViolation:
    """Represents an AKIS gate violation."""
    gate: str
    reason: str
    recovered: bool = True


@dataclass
class WorkflowLog:
    """Parsed workflow log with structured data."""
    # Metadata
    id: str = ""
    date: str = ""
    duration_minutes: int = 0
    complexity: str = "medium"
    domain: str = "unknown"
    branch: str = ""
    
    # Content
    raw_content: str = ""
    markdown_body: str = ""
    
    # Skills
    skills_loaded: List[str] = field(default_factory=list)
    skills_suggested: List[str] = field(default_factory=list)
    skill_triggers: List[SkillTrigger] = field(default_factory=list)
    
    # Files
    files_modified: List[FileChange] = field(default_factory=list)
    files_created: List[FileChange] = field(default_factory=list)
    files_deleted: List[str] = field(default_factory=list)
    file_type_counts: Dict[str, int] = field(default_factory=dict)
    
    # Agents
    agents_delegated: List[AgentDelegation] = field(default_factory=list)
    parallel_pairs: List[List[str]] = field(default_factory=list)
    
    # Commands
    commands: List[CommandExecution] = field(default_factory=list)
    
    # Errors
    errors: List[ErrorInfo] = field(default_factory=list)
    
    # Gates
    gates_passed: List[str] = field(default_factory=list)
    gate_violations: List[GateViolation] = field(default_factory=list)
    
    # Root causes
    root_causes: List[RootCause] = field(default_factory=list)
    
    # Knowledge
    entities_added: List[Dict[str, str]] = field(default_factory=list)
    gotchas_learned: List[str] = field(default_factory=list)
    patterns_discovered: List[str] = field(default_factory=list)
    
    # Parsing info
    has_yaml_front_matter: bool = False
    parse_errors: List[str] = field(default_factory=list)


class WorkflowLogParser:
    """Parser for workflow logs with YAML front matter support."""
    
    # Legacy keyword patterns for backward compatibility
    DOMAIN_KEYWORDS = {
        'frontend_only': ['react', 'tsx', 'jsx', 'component', 'zustand', 'tailwind'],
        'backend_only': ['fastapi', 'sqlalchemy', 'endpoint', 'api route', 'alembic'],
        'fullstack': ['frontend', 'backend'],
        'docker_heavy': ['docker', 'container', 'compose', 'dockerfile'],
        'documentation': ['readme', 'docs/', 'documentation', 'changelog'],
        'testing': ['pytest', 'jest', 'test_', '.test.', 'coverage'],
        'debugging': ['error', 'bug', 'fix', 'traceback', 'exception'],
    }
    
    SKILL_KEYWORDS = {
        'frontend-react': ['react', 'tsx', 'jsx', 'component', 'zustand', 'hook'],
        'backend-api': ['fastapi', 'sqlalchemy', 'endpoint', 'python', 'async'],
        'docker': ['docker', 'container', 'compose'],
        'testing': ['pytest', 'jest', 'test', 'coverage'],
        'debugging': ['error', 'bug', 'fix', 'debug', 'traceback'],
        'documentation': ['docs', 'readme', 'markdown'],
        'ci-cd': ['workflow', 'github actions', 'deploy', 'pipeline'],
    }
    
    def __init__(self, workflow_dir: Path):
        self.workflow_dir = Path(workflow_dir)
        self.logs: List[WorkflowLog] = []
        
    def load_all(self) -> List[WorkflowLog]:
        """Load and parse all workflow logs."""
        self.logs = []
        if not self.workflow_dir.exists():
            return self.logs
            
        for log_file in sorted(self.workflow_dir.glob("*.md")):
            if log_file.name in ['README.md', 'WORKFLOW_LOG_FORMAT.md']:
                continue
            try:
                log = self.parse_file(log_file)
                self.logs.append(log)
            except Exception as e:
                # Create minimal log entry for parse failures
                log = WorkflowLog(id=log_file.stem, parse_errors=[str(e)])
                self.logs.append(log)
                
        return self.logs
    
    def parse_file(self, file_path: Path) -> WorkflowLog:
        """Parse a single workflow log file."""
        content = file_path.read_text(encoding='utf-8')
        log = WorkflowLog(id=file_path.stem, raw_content=content)
        
        # Try YAML front matter parsing first
        if content.startswith('---'):
            log = self._parse_yaml_front_matter(content, log)
        else:
            log = self._parse_legacy_format(content, log)
            
        return log
    
    def _parse_yaml_front_matter(self, content: str, log: WorkflowLog) -> WorkflowLog:
        """Parse YAML front matter from log content."""
        # Extract YAML between --- delimiters
        match = re.match(r'^---\n(.*?)\n---\n?(.*)', content, re.DOTALL)
        if not match:
            return self._parse_legacy_format(content, log)
            
        yaml_content = match.group(1)
        log.markdown_body = match.group(2)
        log.has_yaml_front_matter = True
        
        try:
            data = yaml.safe_load(yaml_content)
            if not isinstance(data, dict):
                log.parse_errors.append("YAML front matter is not a dictionary")
                return self._parse_legacy_format(content, log)
        except yaml.YAMLError as e:
            log.parse_errors.append(f"YAML parse error: {e}")
            return self._parse_legacy_format(content, log)
        
        # Parse session metadata
        session = data.get('session', {})
        log.id = session.get('id', log.id)
        log.date = session.get('date', '')
        log.duration_minutes = session.get('duration_minutes', 0)
        log.complexity = session.get('complexity', 'medium')
        log.domain = session.get('domain', 'unknown')
        log.branch = session.get('branch', '')
        
        # Parse skills
        skills = data.get('skills', {})
        log.skills_loaded = skills.get('loaded', [])
        log.skills_suggested = skills.get('suggested', [])
        for trigger in skills.get('triggers', []):
            if isinstance(trigger, dict):
                log.skill_triggers.append(SkillTrigger(
                    skill=trigger.get('skill', ''),
                    trigger=trigger.get('trigger', '')
                ))
        
        # Parse files
        files = data.get('files', {})
        for f in files.get('modified', []):
            if isinstance(f, dict):
                log.files_modified.append(FileChange(
                    path=f.get('path', ''),
                    type=f.get('type', ''),
                    domain=f.get('domain', ''),
                    changes=f.get('changes', '')
                ))
        for f in files.get('created', []):
            if isinstance(f, dict):
                log.files_created.append(FileChange(
                    path=f.get('path', ''),
                    type=f.get('type', ''),
                    domain=f.get('domain', ''),
                    changes=f.get('changes', '')
                ))
        log.files_deleted = files.get('deleted', [])
        log.file_type_counts = files.get('summary', {})
        
        # Parse agents
        agents = data.get('agents', {})
        for a in agents.get('delegated', []):
            if isinstance(a, dict):
                log.agents_delegated.append(AgentDelegation(
                    name=a.get('name', ''),
                    task=a.get('task', ''),
                    result=a.get('result', 'success'),
                    duration_minutes=a.get('duration_minutes', 0)
                ))
        log.parallel_pairs = agents.get('parallel_pairs', [])
        
        # Parse commands
        for cmd in data.get('commands', []):
            if isinstance(cmd, dict):
                log.commands.append(CommandExecution(
                    cmd=cmd.get('cmd', ''),
                    domain=cmd.get('domain', ''),
                    success=cmd.get('success', True),
                    output_summary=cmd.get('output_summary', ''),
                    error=cmd.get('error', '')
                ))
        
        # Parse errors
        for err in data.get('errors', []):
            if isinstance(err, dict):
                log.errors.append(ErrorInfo(
                    type=err.get('type', ''),
                    message=err.get('message', ''),
                    file=err.get('file', ''),
                    line=err.get('line', 0),
                    fixed=err.get('fixed', False),
                    root_cause=err.get('root_cause', ''),
                    skill_used=err.get('skill_used', '')
                ))
        
        # Parse gates
        gates = data.get('gates', {})
        log.gates_passed = gates.get('passed', [])
        for v in gates.get('violations', []):
            if isinstance(v, dict):
                log.gate_violations.append(GateViolation(
                    gate=v.get('gate', ''),
                    reason=v.get('reason', ''),
                    recovered=v.get('recovered', True)
                ))
        
        # Parse root causes
        for rc in data.get('root_causes', []):
            if isinstance(rc, dict):
                log.root_causes.append(RootCause(
                    problem=rc.get('problem', ''),
                    solution=rc.get('solution', ''),
                    category=rc.get('category', 'bug'),
                    skill=rc.get('skill', '')
                ))
        
        # Parse knowledge
        knowledge = data.get('knowledge', {})
        log.entities_added = knowledge.get('entities_added', [])
        log.gotchas_learned = knowledge.get('gotchas_learned', [])
        log.patterns_discovered = knowledge.get('patterns_discovered', [])
        
        return log
    
    def _parse_legacy_format(self, content: str, log: WorkflowLog) -> WorkflowLog:
        """Parse legacy markdown format using keyword matching."""
        log.markdown_body = content
        content_lower = content.lower()
        
        # Detect domain from keywords
        for domain, keywords in self.DOMAIN_KEYWORDS.items():
            if domain == 'fullstack':
                # Special case: need both frontend and backend
                if 'frontend' in content_lower and 'backend' in content_lower:
                    log.domain = 'fullstack'
                    break
            else:
                for kw in keywords:
                    if kw in content_lower:
                        log.domain = domain
                        break
        
        # Detect skills from keywords
        for skill, keywords in self.SKILL_KEYWORDS.items():
            for kw in keywords:
                if kw in content_lower:
                    if skill not in log.skills_loaded:
                        log.skills_loaded.append(skill)
                    break
        
        # Extract "Skills Loaded" section if present
        skills_match = re.search(r'## Skills Loaded\n+(.+?)(?=\n##|\Z)', content, re.DOTALL)
        if skills_match:
            skills_text = skills_match.group(1)
            for skill in re.findall(r'[-*]\s*(\S+)', skills_text):
                skill_clean = skill.strip().lower()
                if skill_clean not in log.skills_loaded:
                    log.skills_loaded.append(skill_clean)
        
        # Extract files from "Files Modified" table
        files_match = re.search(r'\| File \| Changes \|.*?\n\|[-:]+\|[-:]+\|(.*?)(?=\n\n|\n##|\Z)', content, re.DOTALL)
        if files_match:
            for row in re.findall(r'\| `?([^`|]+)`? \| ([^|]+) \|', files_match.group(1)):
                path = row[0].strip()
                changes = row[1].strip()
                file_type = path.split('.')[-1] if '.' in path else ''
                domain = 'frontend' if any(x in path for x in ['frontend', 'src/components']) else 'backend'
                log.files_modified.append(FileChange(path=path, type=file_type, domain=domain, changes=changes))
        
        # Extract root causes
        for match in re.finditer(
            r'(?:problem|issue|error|bug):\s*(.+?)(?:\n|$).*?(?:solution|fix|resolved):\s*(.+?)(?:\n|$)',
            content_lower,
            re.IGNORECASE | re.DOTALL
        ):
            log.root_causes.append(RootCause(
                problem=match.group(1).strip()[:100],
                solution=match.group(2).strip()[:200]
            ))
        
        # Extract date from filename if possible
        date_match = re.match(r'(\d{4}-\d{2}-\d{2})', log.id)
        if date_match:
            log.date = date_match.group(1)
        
        # Estimate complexity from file count
        if len(log.files_modified) <= 2:
            log.complexity = 'simple'
        elif len(log.files_modified) <= 5:
            log.complexity = 'medium'
        else:
            log.complexity = 'complex'
            
        return log
    
    def get_aggregate_stats(self) -> Dict[str, Any]:
        """Get aggregate statistics across all logs."""
        stats = {
            'total_logs': len(self.logs),
            'logs_with_yaml': sum(1 for l in self.logs if l.has_yaml_front_matter),
            'logs_legacy': sum(1 for l in self.logs if not l.has_yaml_front_matter),
            
            # Domain distribution
            'domains': defaultdict(int),
            
            # Skill usage
            'skills': defaultdict(int),
            'skill_pairs': defaultdict(int),
            
            # Complexity distribution
            'complexity': defaultdict(int),
            
            # Agent usage
            'agents': defaultdict(int),
            
            # Error types
            'error_types': defaultdict(int),
            
            # File types
            'file_types': defaultdict(int),
            
            # Root cause categories
            'root_cause_categories': defaultdict(int),
            
            # Gate compliance
            'total_gate_violations': 0,
            'gate_violation_types': defaultdict(int),
        }
        
        for log in self.logs:
            stats['domains'][log.domain] += 1
            stats['complexity'][log.complexity] += 1
            
            for skill in log.skills_loaded:
                stats['skills'][skill] += 1
            
            # Track skill pairs
            skills = sorted(log.skills_loaded)
            for i, s1 in enumerate(skills):
                for s2 in skills[i+1:]:
                    stats['skill_pairs'][f"{s1}+{s2}"] += 1
            
            for agent in log.agents_delegated:
                stats['agents'][agent.name] += 1
            
            for error in log.errors:
                stats['error_types'][error.type] += 1
            
            for f in log.files_modified + log.files_created:
                stats['file_types'][f.type] += 1
            
            for rc in log.root_causes:
                stats['root_cause_categories'][rc.category] += 1
            
            stats['total_gate_violations'] += len(log.gate_violations)
            for v in log.gate_violations:
                stats['gate_violation_types'][v.gate] += 1
        
        # Convert defaultdicts to regular dicts for JSON serialization
        for key in stats:
            if isinstance(stats[key], defaultdict):
                stats[key] = dict(stats[key])
        
        return stats
    
    def suggest_skills(self, recent_n: int = 5) -> List[Dict[str, Any]]:
        """Suggest skills based on recent log patterns."""
        recent_logs = self.logs[-recent_n:] if len(self.logs) >= recent_n else self.logs
        
        suggestions = []
        
        # Aggregate skill usage from recent logs
        skill_counts = defaultdict(int)
        skill_triggers = defaultdict(list)
        
        for log in recent_logs:
            for skill in log.skills_loaded:
                skill_counts[skill] += 1
            for trigger in log.skill_triggers:
                skill_triggers[trigger.skill].append(trigger.trigger)
        
        # Find frequently used skills
        for skill, count in sorted(skill_counts.items(), key=lambda x: -x[1]):
            if count >= 2:  # Used at least twice recently
                suggestions.append({
                    'skill': skill,
                    'usage_count': count,
                    'triggers': skill_triggers.get(skill, []),
                    'recommendation': 'frequently_used'
                })
        
        # Find suggested but not used skills
        for log in recent_logs:
            for skill in log.skills_suggested:
                if skill not in skill_counts:
                    suggestions.append({
                        'skill': skill,
                        'usage_count': 0,
                        'triggers': [],
                        'recommendation': 'suggested_not_used'
                    })
        
        return suggestions
    
    def suggest_agents(self, recent_n: int = 5) -> List[Dict[str, Any]]:
        """Suggest agents based on recent log patterns."""
        recent_logs = self.logs[-recent_n:] if len(self.logs) >= recent_n else self.logs
        
        suggestions = []
        agent_stats = defaultdict(lambda: {'count': 0, 'success': 0, 'tasks': []})
        
        for log in recent_logs:
            for agent in log.agents_delegated:
                agent_stats[agent.name]['count'] += 1
                if agent.result == 'success':
                    agent_stats[agent.name]['success'] += 1
                agent_stats[agent.name]['tasks'].append(agent.task)
        
        for agent, stats in agent_stats.items():
            success_rate = stats['success'] / stats['count'] if stats['count'] > 0 else 0
            suggestions.append({
                'agent': agent,
                'usage_count': stats['count'],
                'success_rate': success_rate,
                'tasks': stats['tasks'][:3],  # Top 3 tasks
                'recommendation': 'effective' if success_rate >= 0.8 else 'needs_improvement'
            })
        
        return suggestions
    
    def extract_gotchas(self) -> List[Dict[str, str]]:
        """Extract problem→solution patterns from all logs."""
        gotchas = []
        seen = set()
        
        for log in self.logs:
            for rc in log.root_causes:
                key = (rc.problem[:50], rc.solution[:50])
                if key not in seen:
                    seen.add(key)
                    gotchas.append({
                        'problem': rc.problem,
                        'solution': rc.solution,
                        'category': rc.category,
                        'skill': rc.skill,
                        'source': log.id
                    })
        
        return gotchas


# Standalone usage
if __name__ == '__main__':
    import json
    from pathlib import Path
    
    root = Path(__file__).parent.parent.parent
    workflow_dir = root / 'log' / 'workflow'
    
    parser = WorkflowLogParser(workflow_dir)
    logs = parser.load_all()
    
    print(f"📂 Parsed {len(logs)} workflow logs")
    print(f"  - YAML format: {sum(1 for l in logs if l.has_yaml_front_matter)}")
    print(f"  - Legacy format: {sum(1 for l in logs if not l.has_yaml_front_matter)}")
    
    stats = parser.get_aggregate_stats()
    print(f"\n📊 Aggregate Statistics:")
    print(f"  Domains: {stats['domains']}")
    print(f"  Skills: {stats['skills']}")
    print(f"  Complexity: {stats['complexity']}")
    
    suggestions = parser.suggest_skills()
    print(f"\n💡 Skill Suggestions: {len(suggestions)}")
    for s in suggestions[:5]:
        print(f"  - {s['skill']}: {s['recommendation']} (used {s['usage_count']}x)")
    
    gotchas = parser.extract_gotchas()
    print(f"\n⚠️ Gotchas Found: {len(gotchas)}")
    for g in gotchas[:3]:
        print(f"  - {g['problem'][:50]}...")
