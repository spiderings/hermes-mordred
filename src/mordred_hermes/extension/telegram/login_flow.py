"""Step-by-step Telegram login for UIs (phone → code → optional 2FA password).

The CLI logs in within one interactive call; a desktop dialog needs the same
login split across requests. :class:`LoginFlow` keeps the half-authenticated
Telethon client between steps (in the process's memory only), seals the
resulting session with the Secure Enclave on success, and revokes a session
Telegram already accepted if anything fails afterwards.

Nothing entered here is stored or logged: the phone number, code and 2FA
password live only in the flow object while it runs; errors are codes.
"""

from __future__ import annotations

import asyncio
import contextlib
import secrets as _secrets
import time
from dataclasses import dataclass, field, replace
from typing import Any

from .readonly import RequestPolicy
from .secrets import TelegramSecrets, TelegramSecretsError, new_store_key, validate_api_credentials

FLOW_TTL_SECONDS = 600.0


class LoginError(RuntimeError):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


@dataclass
class LoginFlow:
    flow_id: str
    base: TelegramSecrets
    client: Any
    policy: RequestPolicy
    phone: str
    step: str = "code"  # "code" | "password" | "done"
    created: float = field(default_factory=time.monotonic)

    @property
    def expired(self) -> bool:
        return time.monotonic() - self.created > FLOW_TTL_SECONDS


class LoginFlows:
    """At most a handful of concurrent flows per process, each with a TTL."""

    def __init__(self, store: Any, client_factory: Any = None, save_session: Any = None) -> None:
        self._store = store
        self._client_factory = client_factory
        self._save_session = save_session
        self._flows: dict[str, LoginFlow] = {}
        self._lock = asyncio.Lock()

    def _factory(self) -> Any:
        if self._client_factory is not None:
            return self._client_factory
        from .client import build_client

        return build_client

    def _saver(self) -> Any:
        if self._save_session is not None:
            return self._save_session
        from .client import save_session

        return save_session

    async def _reap(self) -> None:
        for fid, flow in list(self._flows.items()):
            if flow.expired:
                await self.cancel(fid)

    async def start(self, *, api_id: Any, api_hash: Any, phone: Any) -> LoginFlow:
        """Store nothing yet; connect and ask Telegram to send the login code."""
        await self._reap()
        if not isinstance(phone, str) or not phone.strip().lstrip("+").replace(" ", "").isdigit():
            raise LoginError("invalid_phone")
        current = await asyncio.to_thread(self._store.load)
        if current is not None and current.session is not None:
            raise LoginError("telegram_already_logged_in")
        if current is not None and current.has_api:
            base = current
        else:
            try:
                valid_id, valid_hash = validate_api_credentials(api_id, api_hash)
            except TelegramSecretsError as exc:
                raise LoginError(exc.code) from exc
            await asyncio.to_thread(self._store.ensure_key)
            base = (
                replace(current, api_id=valid_id, api_hash=valid_hash)
                if current is not None
                else TelegramSecrets(api_id=valid_id, api_hash=valid_hash, store_key=new_store_key())
            )
        policy = RequestPolicy(login=True)
        client = self._factory()(base.api_id, base.api_hash, None, policy=policy)
        number = phone.strip().replace(" ", "")
        try:
            await client.connect()
            await client.send_code_request(number)
        except Exception as exc:
            with contextlib.suppress(Exception):
                await client.disconnect()
            raise LoginError(_telethon_code(exc, "telegram_login_failed")) from exc
        flow = LoginFlow(_secrets.token_urlsafe(16), base, client, policy, number)
        self._flows[flow.flow_id] = flow
        return flow

    def get(self, flow_id: str) -> LoginFlow:
        flow = self._flows.get(flow_id)
        if flow is None or flow.expired:
            raise LoginError("login_flow_expired")
        return flow

    async def submit_code(self, flow_id: str, code: Any) -> str:
        flow = self.get(flow_id)
        if flow.step != "code" or not isinstance(code, str) or not code.strip():
            raise LoginError("invalid_request")
        try:
            await flow.client.sign_in(phone=flow.phone, code=code.strip())
        except Exception as exc:
            if type(exc).__name__ == "SessionPasswordNeededError":
                flow.step = "password"
                return flow.step
            raise LoginError(_telethon_code(exc, "telegram_login_failed")) from exc
        return await self._finish(flow)

    async def submit_password(self, flow_id: str, password: Any) -> str:
        flow = self.get(flow_id)
        if flow.step != "password" or not isinstance(password, str) or not password:
            raise LoginError("invalid_request")
        try:
            await flow.client.sign_in(password=password)
        except Exception as exc:
            raise LoginError(_telethon_code(exc, "telegram_login_failed")) from exc
        return await self._finish(flow)

    async def _finish(self, flow: LoginFlow) -> str:
        try:
            session = self._saver()(flow.client)
            sealed = replace(flow.base, session=session)
            # ``flow.base`` already carries everything read at start(); the old
            # load()-then-update(lambda _old: sealed) discarded both unsealed
            # values, costing two extra Enclave unwraps (two Touch ID / password
            # dialogs) for nothing. Sealing only needs the public key.
            await asyncio.to_thread(self._store.store, sealed)
        except BaseException:
            # Telegram accepted the login; do not leave an unrevocable session.
            with contextlib.suppress(Exception):
                flow.policy.logout = True
                await flow.client.log_out()
            await self.cancel(flow.flow_id)
            raise
        flow.step = "done"
        await self.cancel(flow.flow_id)
        return "done"

    async def cancel(self, flow_id: str) -> None:
        flow = self._flows.pop(flow_id, None)
        if flow is not None:
            with contextlib.suppress(Exception):
                await flow.client.disconnect()


_TELETHON_CODES = {
    "PhoneCodeInvalidError": "login_code_invalid",
    "PhoneCodeExpiredError": "login_code_expired",
    "PasswordHashInvalidError": "login_password_invalid",
    "PhoneNumberInvalidError": "invalid_phone",
    "PhoneNumberBannedError": "phone_banned",
    "FloodWaitError": "telegram_rate_limited",
    "ApiIdInvalidError": "invalid_api_credentials",
}


def _telethon_code(exc: BaseException, fallback: str) -> str:
    for cls in type(exc).__mro__:
        code = _TELETHON_CODES.get(cls.__name__)
        if code is not None:
            return code
    return getattr(exc, "code", None) or fallback
