"""Vault API schemas. Values are write-only: no response model carries them."""

import uuid
from datetime import datetime
from typing import Annotated

from pydantic import BaseModel, Field, SecretStr

from app.iam.schemas import StrictIn
from app.vault.keys import SecretPurpose

SecretName = Annotated[str, Field(pattern=r"^[a-z0-9][a-z0-9_.-]{0,63}$")]
Description = Annotated[str, Field(max_length=500)]
SecretValue = Annotated[SecretStr, Field(min_length=1, max_length=16384)]


class SecretCreate(StrictIn):
    name: SecretName
    purpose: SecretPurpose
    description: Description = ""
    value: SecretValue


class SecretValueIn(StrictIn):
    value: SecretValue


class SecretUpdate(StrictIn):
    description: Description


class SecretOut(BaseModel):
    id: uuid.UUID
    name: str
    purpose: str
    description: str
    hint_last4: str = Field(description="Last 4 characters, only for values of 16 or more.")
    value_updated_at: datetime
    created_at: datetime
    version: int
