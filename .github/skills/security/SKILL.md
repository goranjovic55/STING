---
name: security
description: Load when reviewing security vulnerabilities, injection risks, authentication issues, or OWASP compliance. Provides security audit patterns and common vulnerability fixes.
---

# Security

## Triggers
| Pattern | Action |
|---------|--------|
| security vulnerability injection | Load this skill |
| auth bypass brute force | Load this skill |
| OWASP XSS CSRF SQLi | Load this skill |
| CVE exploit payload | Load this skill |

## OWASP Top 10 Checklist

| Risk | Check | Fix |
|------|-------|-----|
| A01 Broken Access | Role-based checks on all endpoints | Add `@requires_auth` decorator |
| A02 Crypto Failures | Secrets in env, not code | Use `os.getenv()`, never hardcode |
| A03 Injection | User input sanitized | Use parameterized queries, escape output |
| A04 Insecure Design | Threat modeling done | Review with security lens |
| A05 Misconfiguration | Debug mode off in prod | Set `DEBUG=False`, check CORS |
| A06 Vulnerable Components | Dependencies up to date | Run `pip-audit`, `npm audit` |
| A07 Auth Failures | Rate limiting, MFA | Add rate limits, session expiry |
| A08 Data Integrity | Input validation | Validate all user inputs server-side |
| A09 Logging Failures | Security events logged | Log auth, access, errors |
| A10 SSRF | URL validation | Whitelist allowed domains |

## Common Vulnerabilities (NOP-specific)

| Location | Risk | Mitigation |
|----------|------|------------|
| WebSocket endpoints | No auth check | Validate token on connect |
| Traffic capture | Raw packet access | Sanitize before display |
| Workflow executor | Code injection via variables | Sandbox execution, validate input |
| Agent commands | RCE via shell injection | Use subprocess with shell=False |
| API endpoints | Mass assignment | Use Pydantic schemas, explicit fields |
| File operations | Path traversal | Validate paths, use basedir checks |

## Security Patterns

```python
# Pattern 1: Parameterized query (SQLAlchemy)
# ❌ Bad: f"SELECT * FROM users WHERE id = {user_id}"
# ✅ Good:
result = await db.execute(
    select(User).where(User.id == user_id)
)

# Pattern 2: Input validation (FastAPI)
from pydantic import validator

class UserInput(BaseModel):
    username: str
    
    @validator('username')
    def validate_username(cls, v):
        if not v.isalnum():
            raise ValueError('Alphanumeric only')
        return v

# Pattern 3: Secure subprocess
import subprocess
# ❌ Bad: subprocess.run(f"ping {host}", shell=True)
# ✅ Good:
subprocess.run(["ping", "-c", "1", host], shell=False)

# Pattern 4: Path traversal prevention
from pathlib import Path

def safe_path(base_dir: str, user_path: str) -> Path:
    base = Path(base_dir).resolve()
    target = (base / user_path).resolve()
    if not str(target).startswith(str(base)):
        raise ValueError("Path traversal detected")
    return target
```

## Audit Checklist

| Category | Check |
|----------|-------|
| Auth | All endpoints require authentication? |
| Auth | Tokens expire and can be revoked? |
| Input | All user input validated server-side? |
| Output | HTML output escaped? |
| Secrets | No secrets in code/logs? |
| Dependencies | No known CVEs in deps? |
| Logging | Failed auth attempts logged? |
| Rate Limit | Brute force protection enabled? |

## Rules

| Rule | Why |
|------|-----|
| Never trust user input | All input is malicious until validated |
| Defense in depth | Multiple security layers |
| Least privilege | Minimal permissions required |
| Fail secure | Errors deny access, not grant |
| Log security events | Audit trail for incidents |

## References
- [OWASP Top 10](https://owasp.org/Top10/)
- [OWASP Cheat Sheets](https://cheatsheetseries.owasp.org/)
- NOP: `backend/app/core/security.py`
