"""Read-only MTProto request allowlist for the Telegram importer.

The importer holds a full Telegram user session: MTProto itself has no scoped
or read-only credential, so the *client* is the only place a read-only promise
can be enforced. Every request Telethon is about to send passes through
:func:`check_request`; anything not on the allowlist raises
:class:`ReadOnlyViolation` before a byte leaves the process.

The allowlist names requests by ``<namespace>.<ClassName>`` (the Telethon TL
module suffix plus the request class) so that e.g. ``messages.GetMessages``
and ``channels.GetMessages`` are distinct entries. It deliberately excludes:

- anything that sends, edits, forwards, deletes, or reacts;
- ``messages.ReadHistory`` / ``channels.ReadHistory`` — importing must not
  change what the account owner's other devices show as read;
- ``account.UpdateStatus`` — importing must not mark the account online;
- media downloads (``upload.*``) — v1 imports text only.

Login requests are allowed only while :attr:`RequestPolicy.login` is enabled
by the interactive CLI login flow; the long-running importer never enables it.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

# Wrapper requests Telethon uses to (re)initialize a connection. They carry the
# real request in ``.query``; the inner request is what gets checked.
_WRAPPERS = frozenset(
    {
        "functions.InvokeWithLayerRequest",
        "functions.InitConnectionRequest",
        "functions.InvokeWithoutUpdatesRequest",
    }
)

# Pure reads needed to enumerate dialogs and page through their history, plus
# the transport-level keepalives the MTProto sender issues on its own.
READ_REQUESTS = frozenset(
    {
        "functions.PingRequest",
        "functions.PingDelayDisconnectRequest",
        "functions.GetFutureSaltsRequest",
        "help.GetConfigRequest",
        "help.GetNearestDcRequest",
        "updates.GetStateRequest",
        "users.GetUsersRequest",
        "users.GetFullUserRequest",
        "messages.GetDialogsRequest",
        "messages.GetPeerDialogsRequest",
        "messages.GetHistoryRequest",
        "messages.GetMessagesRequest",
        "messages.GetChatsRequest",
        "messages.GetFullChatRequest",
        "messages.GetForumTopicsRequest",
        "channels.GetChannelsRequest",
        "channels.GetFullChannelRequest",
        "channels.GetMessagesRequest",
    }
)

# Interactive login (phone code, then the optional 2FA password).
LOGIN_REQUESTS = frozenset(
    {
        "auth.SendCodeRequest",
        "auth.ResendCodeRequest",
        "auth.SignInRequest",
        "account.GetPasswordRequest",
        "auth.CheckPasswordRequest",
    }
)

# Revoking the importer's own session on ``telegram logout``.
LOGOUT_REQUESTS = frozenset({"auth.LogOutRequest"})


class ReadOnlyViolation(RuntimeError):
    """A request outside the read-only allowlist was about to be sent.

    Deliberately NOT an ``OSError``/``PermissionError``: Telethon treats
    ``OSError`` as "network down" and would retry a blocked request forever.
    """

    def __init__(self, request_name: str) -> None:
        super().__init__(f"telegram_request_blocked: {request_name}")
        self.request_name = request_name


@dataclass
class RequestPolicy:
    """Which request classes the client may currently send."""

    login: bool = False
    logout: bool = False

    def allowed(self, name: str) -> bool:
        if name in READ_REQUESTS:
            return True
        if self.login and name in LOGIN_REQUESTS:
            return True
        return self.logout and name in LOGOUT_REQUESTS


def request_name(request: Any) -> str:
    """Return ``<namespace>.<ClassName>`` for a Telethon TL request object."""
    cls = type(request)
    namespace = cls.__module__.rsplit(".", 1)[-1]
    return f"{namespace}.{cls.__name__}"


def check_request(request: Any, policy: RequestPolicy) -> None:
    """Raise :class:`ReadOnlyViolation` unless *request* is allowed.

    Lists (Telethon batches) are checked element by element; connection
    wrappers are unwrapped to the request they carry.
    """
    if isinstance(request, list | tuple):
        for item in request:
            check_request(item, policy)
        return
    name = request_name(request)
    depth = 0
    while name in _WRAPPERS:
        depth += 1
        inner = getattr(request, "query", None)
        if inner is None or depth > 4:
            raise ReadOnlyViolation(name)
        request = inner
        name = request_name(request)
    if not policy.allowed(name):
        raise ReadOnlyViolation(name)
