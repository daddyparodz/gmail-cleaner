"""
Application Configuration
-------------------------
Central configuration and settings for the application.
"""

import os
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    """Application settings loaded from environment variables."""

    # Server
    app_name: str = "Gmail Cleaner"
    app_version: str = "1.0.0"
    debug: bool = False
    port: int = 8766
    oauth_port: int = 8767

    # Auth
    web_auth: bool = os.environ.get("WEB_AUTH", "false").lower() == "true"
    oauth_host: str = os.environ.get(
        "OAUTH_HOST", "localhost"
    )  # Custom host for OAuth redirect (e.g., your domain or IP)
    credentials_file: str = "credentials.json"
    token_file: str = "token.json"

    # Gmail API
    scopes: list[str] = [
        "https://www.googleapis.com/auth/gmail.readonly",
        "https://www.googleapis.com/auth/gmail.modify",
    ]

    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"


# Global settings instance
settings = Settings()
