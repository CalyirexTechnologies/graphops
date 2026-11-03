"""Request bodies.

Validation lives here rather than in the routes so the OpenAPI document
describes the real constraints. A reviewer reading /openapi.json sees the
same limits the server enforces, which is the only version of an API spec
worth publishing.
"""
from __future__ import annotations

from pydantic import BaseModel, Field, field_validator


class LoginRequest(BaseModel):
    organization: str = Field(min_length=1, max_length=64,
                              description='Organization slug.')
    email: str = Field(min_length=3, max_length=320)
    password: str = Field(min_length=1, max_length=1024)

    @field_validator('organization')
    @classmethod
    def _slug(cls, value: str) -> str:
        cleaned = value.strip().lower()
        if not cleaned.replace('-', '').replace('_', '').isalnum():
            raise ValueError('organization must be a slug')
        return cleaned


class MfaRequest(BaseModel):
    challenge: str = Field(min_length=10, max_length=4096)
    code: str = Field(min_length=6, max_length=8, pattern=r'^\d{6,8}$')


class RefreshRequest(BaseModel):
    refresh_token: str = Field(min_length=10, max_length=4096)


class ConnectorRunRequest(BaseModel):
    connectors: list[str] | None = Field(
        default=None, max_length=32,
        description='Connector keys to run. Omit to run every inbound one.')
    # Live is accepted but refused without credentials, which is the point:
    # the API should not pretend a mode exists that the deployment cannot use.
    mode: str = Field(default='replay', pattern='^(replay|live)$')


class CreateUserRequest(BaseModel):
    email: str = Field(min_length=3, max_length=320)
    password: str = Field(min_length=12, max_length=1024)
    roles: list[str] = Field(default_factory=lambda: ['viewer'], max_length=8)
    display_name: str = Field(default='', max_length=120)


class CreateApiKeyRequest(BaseModel):
    name: str = Field(min_length=1, max_length=120)
    roles: list[str] = Field(default_factory=lambda: ['service'], max_length=8)


class BlastRadiusRequest(BaseModel):
    node_id: str = Field(min_length=1, max_length=256)
    hops: int = Field(default=3, ge=1, le=6)


class DeliverFindingRequest(BaseModel):
    connector: str = Field(min_length=1, max_length=64)
    finding_id: str = Field(min_length=1, max_length=128)
