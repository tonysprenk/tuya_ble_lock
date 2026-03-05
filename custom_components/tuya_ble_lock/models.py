"""Dataclasses used by the Tuya BLE lock integration."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Optional

if TYPE_CHECKING:
    from .coordinator import TuyaBLELockCoordinator
    from .credential_store import CredentialStore


@dataclass
class TuyaBLELockData:
    coordinator: TuyaBLELockCoordinator
    credential_store: CredentialStore
    profile: dict | None = None
    platforms: list | None = None


@dataclass
class MemberRecord:
    member_id: int
    name: str
    ha_user_id: Optional[str]
    created_at: float


@dataclass
class CredentialRecord:
    credential_id: str
    member_id: int
    lock_entry_id: str
    cred_type: int
    hw_id: int
    name: str
    created_at: float


@dataclass
class TempPasswordRecord:
    password_id: str
    lock_entry_id: str
    name: str
    effective_ts: int
    expiry_ts: int
    created_at: float
