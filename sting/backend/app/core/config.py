# STING 2.0 - Core Configuration
from pydantic_settings import BaseSettings
from functools import lru_cache


class Settings(BaseSettings):
    STING_USERNAME: str = "sting"
    STING_PASSWORD: str = "changeme"
    SECRET_KEY: str = "sting-secret-key-change-in-production"
    DATABASE_URL: str = "postgresql+asyncpg://sting:sting@localhost:5432/sting"
    REDIS_URL: str = "redis://localhost:6379"
    API_HOST: str = "0.0.0.0"
    API_PORT: int = 8700
    SSH_PROXY_PORT: int = 22
    HTTP_PROXY_PORT: int = 80
    SESSION_TTL_MINUTES: int = 60
    MAX_DISK_MB: int = 100
    MAX_MEMORY_MB: int = 256
    MAX_FILES: int = 100

    class Config:
        env_file = ".env"


@lru_cache()
def get_settings():
    return Settings()


settings = get_settings()
