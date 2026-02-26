# Security Patterns

Reusable patterns for security auditing and vulnerability prevention.

## Pattern Files

| Pattern | Description | Usage |
|---------|-------------|-------|
| `input_sanitization.py` | Input validation | Prevent injection |
| `auth_check.py` | Authentication check | Verify tokens |
| `cors_config.py` | CORS configuration | Cross-origin policy |
| `sql_parameterized.py` | Parameterized queries | SQL injection prevention |

## Input Sanitization
```python
from html import escape
from bleach import clean

def sanitize_input(text: str) -> str:
    """Sanitize user input to prevent XSS."""
    return escape(clean(text, strip=True))

def validate_email(email: str) -> bool:
    """Validate email format."""
    import re
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return bool(re.match(pattern, email))
```

## Authentication Check
```python
from fastapi import Depends, HTTPException
from jose import jwt, JWTError

async def get_current_user(token: str = Depends(oauth2_scheme)):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
        if payload.get("exp") < datetime.utcnow().timestamp():
            raise HTTPException(401, "Token expired")
        return payload
    except JWTError:
        raise HTTPException(401, "Invalid token")
```

## CORS Configuration
```python
from fastapi.middleware.cors import CORSMiddleware

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000"],  # Specific origins
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE"],
    allow_headers=["*"],
)
```

## Parameterized Queries
```python
# ❌ NEVER: String concatenation (SQL injection risk)
query = f"SELECT * FROM users WHERE id = {user_id}"

# ✅ ALWAYS: Parameterized query
from sqlalchemy import select
result = await db.execute(select(User).where(User.id == user_id))
```

## Pattern Selection

| Vulnerability | Pattern |
|---------------|---------|
| XSS/Injection | input_sanitization.py |
| Auth bypass | auth_check.py |
| CORS issues | cors_config.py |
| SQL injection | sql_parameterized.py |
