"""
Configuration settings for the API.
Environment variables override defaults.
"""
import os
from dataclasses import dataclass, field
from typing import List


@dataclass
class Settings:
    """API Configuration"""

    # Server
    HOST: str = "0.0.0.0"
    PORT: int = 8000
    DEBUG: bool = False
    ENVIRONMENT: str = "development"

    # CORS
    CORS_ORIGINS: List[str] = field(default_factory=lambda: ["*"])

    # Rate limiting (Level 2+)
    RATE_LIMIT_ENABLED: bool = False
    RATE_LIMIT_REQUESTS: int = 100
    RATE_LIMIT_WINDOW: int = 60  # seconds

    # Database (Level 2+)
    DATABASE_URL: str = "sqlite:///./code_audit.db"
    DB_ECHO: bool = False

    # Redis (Level 3)
    REDIS_URL: str = "redis://localhost:6379/0"

    # Auth (Level 2+)
    SECRET_KEY: str = "change-me-in-production"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 30

    def __post_init__(self):
        """Load from environment variables"""
        for key in self.__dataclass_fields__:
            env_value = os.getenv(key)
            if env_value is not None:
                field_type = self.__dataclass_fields__[key].type
                if field_type == bool:
                    setattr(self, key, env_value.lower() in ("true", "1", "yes"))
                elif field_type == int:
                    setattr(self, key, int(env_value))
                elif field_type == List[str]:
                    setattr(self, key, env_value.split(","))
                else:
                    setattr(self, key, env_value)


# Global settings instance
settings = Settings()
