"""Persistent credential/member database using Home Assistant Store."""

from __future__ import annotations

import time
import uuid
from typing import List, Optional

from homeassistant.helpers.storage import Store

from .const import STORAGE_VERSION, STORAGE_KEY
from .models import MemberRecord, CredentialRecord, TempPasswordRecord


class CredentialStore:
    def __init__(self, hass):
        self._store = Store(hass, STORAGE_VERSION, STORAGE_KEY)
        self._data = None

    async def async_load(self) -> None:
        self._data = await self._store.async_load()
        if not self._data:
            self._data = {"version": STORAGE_VERSION, "members": {}, "credentials": {}, "temp_passwords": {}}

    async def async_save(self) -> None:
        await self._store.async_save(self._data)

    # Members
    def get_members(self) -> List[MemberRecord]:
        return [MemberRecord(**m) for m in self._data["members"].values()]

    def get_member(self, member_id: int) -> Optional[MemberRecord]:
        m = self._data["members"].get(str(member_id))
        return MemberRecord(**m) if m else None

    def get_member_by_name(self, name: str) -> Optional[MemberRecord]:
        for m in self.get_members():
            if m.name == name:
                return m
        return None

    async def async_add_member(self, name: str, ha_user_id: Optional[str] = None) -> MemberRecord:
        member_id = self.next_member_id()
        rec = MemberRecord(member_id=member_id, name=name, ha_user_id=ha_user_id, created_at=time.time())
        self._data["members"][str(member_id)] = rec.__dict__
        await self.async_save()
        return rec

    async def async_update_member(self, member_id: int, **kwargs) -> MemberRecord:
        rec = self.get_member(member_id)
        if not rec:
            raise KeyError("Member not found")
        for k, v in kwargs.items():
            setattr(rec, k, v)
        self._data["members"][str(member_id)] = rec.__dict__
        await self.async_save()
        return rec

    async def async_delete_member(self, member_id: int) -> None:
        self._data["members"].pop(str(member_id), None)
        # also remove credentials
        to_del = [cid for cid, c in self._data["credentials"].items() if c["member_id"] == member_id]
        for cid in to_del:
            self._data["credentials"].pop(cid, None)
        await self.async_save()

    def next_member_id(self) -> int:
        used = {int(k) for k in self._data["members"].keys()}
        for i in range(1, 101):
            if i not in used:
                return i
        raise RuntimeError("no member IDs available")

    # Credentials
    def get_credentials_for_lock(self, lock_entry_id: str) -> List[CredentialRecord]:
        return [CredentialRecord(**c) for c in self._data["credentials"].values() if c["lock_entry_id"] == lock_entry_id]

    def get_credentials_for_member(self, member_id: int) -> List[CredentialRecord]:
        return [CredentialRecord(**c) for c in self._data["credentials"].values() if c["member_id"] == member_id]

    async def async_add_credential(self, member_id, lock_entry_id, cred_type, hw_id, name) -> CredentialRecord:
        cid = str(uuid.uuid4())
        rec = CredentialRecord(
            credential_id=cid,
            member_id=member_id,
            lock_entry_id=lock_entry_id,
            cred_type=cred_type,
            hw_id=hw_id,
            name=name,
            created_at=time.time(),
        )
        self._data["credentials"][cid] = rec.__dict__
        await self.async_save()
        return rec

    async def async_delete_credential(self, credential_id: str) -> Optional[CredentialRecord]:
        rec = self._data["credentials"].pop(credential_id, None)
        if rec:
            await self.async_save()
            return CredentialRecord(**rec)
        return None

    # Temp passwords
    async def async_add_temp_password(self, lock_entry_id, name, effective, expiry) -> TempPasswordRecord:
        pid = str(uuid.uuid4())
        rec = TempPasswordRecord(
            password_id=pid,
            lock_entry_id=lock_entry_id,
            name=name,
            effective_ts=effective,
            expiry_ts=expiry,
            created_at=time.time(),
        )
        self._data["temp_passwords"][pid] = rec.__dict__
        await self.async_save()
        return rec

    async def async_delete_temp_password(self, password_id: str) -> None:
        self._data["temp_passwords"].pop(password_id, None)
        await self.async_save()
