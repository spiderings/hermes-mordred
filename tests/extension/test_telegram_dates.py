"""Date-bounded questions, empty-answer handling, and the saved sync scope."""

from __future__ import annotations

import asyncio
import datetime as dt
import json
from types import SimpleNamespace
from typing import Any

import pytest

from mordred_hermes.extension.egress import EgressRoute
from mordred_hermes.extension.telegram import ask, hermes_tools, secrets, service, store, tee
from mordred_hermes.wizard import telegram_cli


def _ts(day: str, hour: int = 12) -> int:
    return int(dt.datetime.strptime(f"{day} {hour}", "%Y-%m-%d %H").astimezone().timestamp())


def _archive(tmp_path) -> tuple[store.ArchiveStore, store.ArchiveIndex]:
    archive = store.ArchiveStore(b"\x03" * 32, tmp_path)
    archive.append_messages(
        1,
        [
            store.StoredMessage(id=1, date=_ts("2026-09-01"), sender="A", text="old unrelated"),
            store.StoredMessage(id=2, date=_ts("2026-09-09"), sender="A", text="hello there"),
            store.StoredMessage(id=3, date=_ts("2026-09-15", 23), sender="B", text="late on the 15th"),
            store.StoredMessage(id=4, date=_ts("2026-09-16", 1), sender="B", text="after the range"),
        ],
    )
    index = store.ArchiveIndex(
        last_sync=_ts("2026-09-16", 2),
        dialogs={1: store.DialogInfo(1, "group", "G", last_date=_ts("2026-09-16", 1), message_count=4)},
    )
    return archive, index


def test_local_day_bounds_are_inclusive_local_days():
    since, until = ask.local_day_bounds("2026-09-08", "2026-09-15")
    assert since == _ts("2026-09-08", 0) and until == _ts("2026-09-16", 0)
    with pytest.raises(ask.AskError, match="invalid_date"):
        ask.local_day_bounds("2026-09-15", "2026-09-01")
    with pytest.raises(ask.AskError, match="invalid_date"):
        ask.local_day_bounds("15/09/2026", None)


def test_period_questions_use_every_message_in_the_period_regardless_of_words(tmp_path):
    archive, index = _archive(tmp_path)
    since, until = ask.local_day_bounds("2026-09-08", "2026-09-15")
    request = ask.AskRequest(question="どんなメッセージが来てますか", since=since, until=until)
    sel = ask.select_context(archive, index, request, ask.Aliases(enabled=False), budget_tokens=10_000)
    texts = "\n".join(sel.lines)
    assert "hello there" in texts and "late on the 15th" in texts
    assert "old unrelated" not in texts and "after the range" not in texts


def test_prompt_states_today_coverage_and_period(tmp_path):
    archive, index = _archive(tmp_path)
    since, until = ask.local_day_bounds("2026-09-08", "2026-09-15")
    request = ask.AskRequest(question="q", since=since, until=until)
    sel = ask.select_context(archive, index, request, ask.Aliases(), budget_tokens=10_000)
    now = dt.datetime(2026, 9, 28, 10, tzinfo=dt.UTC)
    user = ask.build_messages("q", sel, request=request, last_sync=index.last_sync, now=now)[1]["content"]
    assert user.startswith("Today: 2026-09-28")
    assert "last updated 2026-09-16" in user
    assert "ALL imported messages from 2026-09-08 00:00 to 2026-09-16 00:00" in user


def test_dates_in_prompt_are_local_time(tmp_path):
    ts = _ts("2026-09-15", 23)
    assert ask._iso(ts) == "2026-09-15 23:00"


class _Resp:
    def __init__(self, chunks: list[bytes]):
        self.status = 200
        self._chunks = chunks

        class _C:
            async def iter_any(inner) -> Any:
                for c in self._chunks:
                    yield c

        self.content = _C()

    async def __aenter__(self) -> _Resp:
        return self

    async def __aexit__(self, *_e: object) -> None:
        return None


class _Session:
    def __init__(self, chunks: list[bytes]) -> None:
        self.chunks = chunks
        self.bodies: list[dict[str, Any]] = []

    def post(self, url: str, **kw: Any) -> _Resp:
        self.bodies.append(kw["json"])
        return _Resp(self.chunks)

    def get(self, url: str, **kw: Any) -> Any:
        raise AssertionError

    async def close(self) -> None:
        return None


def _local_service(tmp_path, chunks: list[bytes]) -> tuple[service.TelegramService, _Session]:
    archive, index = _archive(tmp_path / "tg")
    archive.save_index(index)
    value = secrets.TelegramSecrets(
        api_id=1,
        api_hash="ab" * 16,
        store_key=b"\x03" * 32,
        session="s",
        backend="local",
        local_endpoint="http://127.0.0.1:1/v1",
        local_model="m",
    )
    session = _Session(chunks)
    svc = service.TelegramService(
        secret_store=SimpleNamespace(load=lambda fresh=True: value, flags=lambda: {}),
        archive_root=tmp_path / "tg",
        http_session_factory=lambda _r, _t: session,
        route_resolver=lambda _h: EgressRoute(None, None),
        policy_check=lambda _b, _u: None,
    )
    return svc, session


def _delta(text: str) -> bytes:
    return ("data: " + json.dumps({"choices": [{"delta": {"content": text}}]}) + "\n").encode()


def test_empty_answer_is_an_error_not_silence(tmp_path):
    svc, _ = _local_service(tmp_path, [b"data: [DONE]\n"])

    async def run() -> str:
        return "".join([c async for c in svc.ask(ask.AskRequest(question="hello"), lambda _m: None)])

    with pytest.raises(ask.AskError, match="llm_empty_answer"):
        asyncio.run(run())


def test_thinking_blocks_are_removed_across_chunks(tmp_path):
    svc, session = _local_service(
        tmp_path, [_delta("<thi"), _delta("nk>plan..."), _delta("</think>Answer"), _delta(".")]
    )

    async def run() -> str:
        return "".join([c async for c in svc.ask(ask.AskRequest(question="hello"), lambda _m: None)])

    assert asyncio.run(run()) == "Answer."
    assert session.bodies[0]["max_tokens"] == ask.ANSWER_TOKENS


def test_hermes_tool_passes_dates_and_reports_coverage(monkeypatch):
    seen: list[Any] = []

    class _Svc:
        async def ask(self, request: Any, on_meta: Any) -> Any:
            seen.append(request)
            yield "ok"

    monkeypatch.setattr(hermes_tools, "_service", lambda: _Svc())
    monkeypatch.setattr(hermes_tools, "_coverage", lambda: {"archive_updated": "x", "sync_running": False, "hint": ""})
    agent = SimpleNamespace(model="m", base_url="http://127.0.0.1:1/v1")
    out = json.loads(
        asyncio.run(
            hermes_tools.telegram_ask(
                {"question": "q", "start_date": "2026-09-08", "end_date": "2026-09-15"}, parent_agent=agent
            )
        )
    )
    assert out["answer"] == "ok" and out["coverage"]["sync_running"] is False
    assert (seen[0].since, seen[0].until) == ask.local_day_bounds("2026-09-08", "2026-09-15")
    bad = json.loads(asyncio.run(hermes_tools.telegram_ask({"question": "q", "start_date": "9/8"}, parent_agent=agent)))
    assert bad == {"error": "invalid_date"}


def test_archive_busy_reflects_the_sync_lock(tmp_path):
    archive = store.ArchiveStore(b"\x03" * 32, tmp_path)
    assert store.archive_busy(tmp_path) is False
    with archive.locked():
        assert store.archive_busy(tmp_path) is True
    assert store.archive_busy(tmp_path) is False


def test_sync_scope_is_saved_and_used(tmp_path):
    vault = tee.TeeSecretStore(tmp_path / "tg", backend_factory=lambda: None, audit_sink=lambda _e: None)
    assert vault.sync_scope() == {}
    vault.save_sync_scope({"include_channels": False, "include_archived": False, "limit_per_dialog": 500})
    svc = service.TelegramService(secret_store=vault, archive_root=tmp_path / "tg")
    opts = svc.sync_options()
    assert (opts.include_channels, opts.include_archived, opts.limit_per_dialog) == (False, False, 500)
    opts = svc.sync_options({"include_channels": True, "limit_per_dialog": None})
    assert (opts.include_channels, opts.include_archived, opts.limit_per_dialog) == (True, False, 500)


def test_cli_sync_uses_saved_scope_unless_all(monkeypatch):
    used: list[Any] = []

    class _Svc:
        def sync_options(self, overrides: Any) -> Any:
            return service.TelegramService.sync_options(
                SimpleNamespace(
                    _secrets=SimpleNamespace(
                        sync_scope=lambda: {
                            "include_channels": False,
                            "include_archived": False,
                            "limit_per_dialog": 500,
                        }
                    )
                ),
                overrides,
            )

    async def fake_run(_svc: Any, options: Any) -> int:
        used.append(options)
        return 0

    monkeypatch.setattr(telegram_cli, "_run_sync", fake_run)
    assert telegram_cli.telegram_sync(service=_Svc()) == 0
    assert (used[-1].include_channels, used[-1].limit_per_dialog) == (False, 500)
    assert telegram_cli.telegram_sync(service=_Svc(), everything=True) == 0
    assert (used[-1].include_channels, used[-1].include_archived, used[-1].limit_per_dialog) == (True, True, None)


# -- recent-days window and pinned-first sync ------------------------------------------


class _Dialog:
    def __init__(self, did: int, entity: str, last: dt.datetime, *, pinned: bool = False) -> None:
        self.id = did
        self.name = entity
        self.entity = entity
        self.date = last
        self.pinned = pinned
        self.is_user = True
        self.is_group = False


class _Msg:
    def __init__(self, mid: int, when: dt.datetime) -> None:
        self.id = mid
        self.message = f"m{mid}"
        self.date = when
        self.sender = None
        self.out = False
        self.media = None
        self.reply_to = None


_Msg.__name__ = "Message"


class _Client:
    def __init__(self, dialogs: list[_Dialog], history: dict[str, list[_Msg]]) -> None:
        self.dialogs = dialogs
        self.history = history
        self.opened: list[str] = []

    async def get_me(self) -> Any:
        return SimpleNamespace(id=1, first_name="Me", last_name=None)

    async def iter_dialogs(self, archived: bool = False) -> Any:
        if not archived:
            for d in self.dialogs:
                yield d

    async def iter_messages(
        self,
        entity: str,
        *,
        min_id: int = 0,
        limit: int | None = None,
        reverse: bool = False,
        offset_date: dt.datetime | None = None,
    ):
        self.opened.append(entity)
        count = 0
        for m in sorted(self.history[entity], key=lambda m: m.id, reverse=not reverse):
            if m.id <= min_id or (offset_date is not None and reverse and m.date < offset_date):
                continue
            yield m
            count += 1
            if limit is not None and count >= limit:
                return


def test_recent_days_skips_idle_chats_and_old_messages_and_puts_pinned_first(tmp_path):
    from mordred_hermes.extension.telegram import client as tg

    now = dt.datetime(2026, 9, 28, 12, tzinfo=dt.UTC)
    day = dt.timedelta(days=1)
    fake = _Client(
        [
            _Dialog(1, "recent", now - 2 * dt.timedelta(hours=1)),
            _Dialog(2, "idle", now - 10 * day),
            _Dialog(3, "pinned", now - 1 * day, pinned=True),
        ],
        {
            "recent": [_Msg(1, now - 5 * day), _Msg(2, now - 1 * day), _Msg(3, now - dt.timedelta(hours=2))],
            "idle": [_Msg(1, now - 10 * day)],
            "pinned": [_Msg(7, now - 4 * day), _Msg(8, now - 1 * day)],
        },
    )
    archive = store.ArchiveStore(b"\x01" * 32, tmp_path)
    opts = tg.SyncOptions(include_archived=False, since_days=3)
    asyncio.run(tg.sync_archive(fake, archive, options=opts, clock=lambda: now.timestamp()))
    assert fake.opened == ["pinned", "recent"]  # pinned first; the idle chat is never opened
    assert [m.id for m in archive.load_messages(1)] == [2, 3]
    assert [m.id for m in archive.load_messages(3)] == [8]
    assert 2 not in archive.load_index().dialogs


def test_cli_sync_remembers_the_options_it_was_given(monkeypatch):
    saved: list[dict[str, Any]] = []
    scope: dict[str, Any] = {}

    class _Svc:
        _secrets = SimpleNamespace(save_sync_scope=lambda s: (saved.append(s), scope.update(s)))

        def sync_options(self, overrides: Any) -> Any:
            return service.TelegramService.sync_options(
                SimpleNamespace(_secrets=SimpleNamespace(sync_scope=lambda: dict(scope))), overrides
            )

    async def fake_run(_svc: Any, options: Any) -> int:
        return 0

    monkeypatch.setattr(telegram_cli, "_run_sync", fake_run)
    assert telegram_cli.telegram_sync(service=_Svc(), since_days=3, include_archived=False) == 0
    assert saved[-1] == {
        "include_channels": True,
        "include_archived": False,
        "limit_per_dialog": None,
        "since_days": 3,
        "max_group_size": 100,
    }
    count = len(saved)
    assert telegram_cli.telegram_sync(service=_Svc()) == 0  # plain sync reuses it and saves nothing new
    assert len(saved) == count


# -- large groups are opt-in ------------------------------------------------------------


class Channel:  # name matters: _group_size looks the full count up only for channels
    def __init__(self, count: int | None) -> None:
        self.participants_count = count


class _GroupDialog(_Dialog):
    def __init__(self, did: int, entity_name: str, last: dt.datetime, entity: Any) -> None:
        super().__init__(did, entity_name, last)
        self.entity = entity
        self.is_user = False
        self.is_group = True


class _GroupClient(_Client):
    def __init__(self, *args: Any, full_count: int | None = None, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self.full_count = full_count
        self.full_requests = 0

    async def __call__(self, request: Any) -> Any:
        self.full_requests += 1
        return SimpleNamespace(full_chat=SimpleNamespace(participants_count=self.full_count))

    async def iter_messages(self, entity: Any, **kwargs: Any):
        key = entity if isinstance(entity, str) else next(d.name for d in self.dialogs if d.entity is entity)
        async for m in super().iter_messages(key, **kwargs):
            yield m


def _group_fixture(full_count: int | None = None) -> _GroupClient:
    now = dt.datetime(2026, 9, 28, 12, tzinfo=dt.UTC)
    recent = now - dt.timedelta(hours=1)
    return _GroupClient(
        [
            _GroupDialog(-1, "small", recent, Channel(12)),
            _GroupDialog(-2, "huge", recent, Channel(5000)),
            _GroupDialog(-3, "unknown", recent, Channel(None)),
        ],
        {"small": [_Msg(1, recent)], "huge": [_Msg(1, recent)], "unknown": [_Msg(1, recent)]},
        full_count=full_count,
    )


def _sync(fake: Any, tmp_path, **opts: Any) -> list[int]:
    from mordred_hermes.extension.telegram import client as tg

    archive = store.ArchiveStore(b"\x01" * 32, tmp_path)
    now = dt.datetime(2026, 9, 28, 12, tzinfo=dt.UTC).timestamp()
    asyncio.run(tg.sync_archive(fake, archive, options=tg.SyncOptions(**opts), clock=lambda: now))
    return sorted(archive.load_index().dialogs)


def test_large_groups_are_skipped_by_default(tmp_path):
    pytest.importorskip("telethon")  # the size lookup is a real Telethon request
    fake = _group_fixture(full_count=None)
    assert _sync(fake, tmp_path) == [-1]  # huge skipped; unknown size counts as large
    assert fake.full_requests == 1  # only the group whose size was not listed


def test_unknown_size_resolved_by_read_only_lookup(tmp_path):
    pytest.importorskip("telethon")  # the size lookup is a real Telethon request
    assert _sync(_group_fixture(full_count=40), tmp_path) == [-3, -1]


def test_large_groups_on_request(tmp_path):
    assert _sync(_group_fixture(), tmp_path, max_group_size=None) == [-3, -2, -1]
    assert _sync(_group_fixture(full_count=None), tmp_path / "b", max_group_size=10000) == [-2, -1]


def test_full_channel_lookup_is_allow_listed():
    from mordred_hermes.extension.telegram import readonly

    assert "channels.GetFullChannelRequest" in readonly.READ_REQUESTS


def test_group_size_scope_defaults_and_opt_in(tmp_path):
    vault = tee.TeeSecretStore(tmp_path / "tg", backend_factory=lambda: None, audit_sink=lambda _e: None)
    svc = service.TelegramService(secret_store=vault, archive_root=tmp_path / "tg")
    assert svc.sync_options().max_group_size == 100  # nothing saved: large groups skipped
    assert svc.sync_options({"max_group_size": 0}).max_group_size is None  # --include-large-groups
    vault.save_sync_scope({"max_group_size": 0})
    assert svc.sync_options().max_group_size is None  # remembered
    vault.save_sync_scope({"max_group_size": 300})
    assert svc.sync_options().max_group_size == 300


def test_selection_reports_mode_and_candidates(tmp_path):
    archive, index = _archive(tmp_path)
    sel = ask.select_context(archive, index, ask.AskRequest(question="hello"), ask.Aliases(), budget_tokens=10_000)
    assert sel.mode == "keyword" and sel.chats_searched == 1
    since, until = ask.local_day_bounds("2026-09-08", "2026-09-15")
    sel = ask.select_context(
        archive, index, ask.AskRequest(question="q", since=since, until=until), ask.Aliases(), budget_tokens=10_000
    )
    assert (sel.mode, sel.candidates, sel.message_count) == ("period", 2, 2)
    sel = ask.select_context(
        archive, index, ask.AskRequest(question="q", dialog_ids=(1,)), ask.Aliases(), budget_tokens=40
    )
    assert sel.mode == "chats" and sel.truncated and sel.candidates == 4


# -- never request the same messages twice ------------------------------------------------


def _counting_client(now: dt.datetime) -> _Client:
    hour = dt.timedelta(hours=1)
    fake = _Client(
        [_Dialog(1, "busy", now - hour), _Dialog(2, "service-only", now - hour)],
        {"busy": [_Msg(1, now - 3 * hour), _Msg(2, now - 2 * hour)], "service-only": [SimpleNamespace(id=9, date=now)]},
    )
    for d in fake.dialogs:
        d.message = SimpleNamespace(id=max(m.id for m in fake.history[d.name]))
    return fake


def test_second_sync_requests_nothing_for_unchanged_chats(tmp_path):
    from mordred_hermes.extension.telegram import client as tg

    now = dt.datetime(2026, 9, 28, 12, tzinfo=dt.UTC)
    fake = _counting_client(now)
    archive = store.ArchiveStore(b"\x01" * 32, tmp_path)
    opts = tg.SyncOptions(max_group_size=None)
    asyncio.run(tg.sync_archive(fake, archive, options=opts, clock=lambda: now.timestamp()))
    assert sorted(fake.opened) == ["busy", "service-only"]
    index = archive.load_index()
    assert index.dialogs[2].last_message_id == 9  # a chat with only service messages is still "seen"

    fake.opened.clear()
    result = asyncio.run(tg.sync_archive(fake, archive, options=opts, clock=lambda: now.timestamp()))
    assert fake.opened == [] and result.messages_imported == 0

    fake.history["busy"].append(_Msg(3, now))
    fake.dialogs[0].message = SimpleNamespace(id=3)
    fake.opened.clear()
    result = asyncio.run(tg.sync_archive(fake, archive, options=opts, clock=lambda: now.timestamp()))
    assert fake.opened == ["busy"] and result.messages_imported == 1
    assert [m.id for m in archive.load_messages(1)] == [1, 2, 3]


def test_interrupted_window_sync_resumes_without_refetching(tmp_path, monkeypatch):
    from mordred_hermes.extension.telegram import client as tg

    monkeypatch.setattr(tg, "_FLUSH_EVERY", 2)
    now = dt.datetime(2026, 9, 28, 12, tzinfo=dt.UTC)
    minute = dt.timedelta(minutes=1)
    msgs = [_Msg(i, now - (10 - i) * minute) for i in range(1, 6)]
    fake = _Client([_Dialog(1, "chat", now)], {"chat": msgs})
    archive = store.ArchiveStore(b"\x01" * 32, tmp_path)
    opts = tg.SyncOptions(since_days=1, max_group_size=None)

    class Stop(Exception):
        pass

    original = fake.iter_messages

    async def dying(entity: str, **kw: Any):
        async for m in original(entity, **kw):
            if m.id == 4:
                raise Stop()
            yield m

    fake.iter_messages = dying
    with pytest.raises(Stop):
        asyncio.run(tg.sync_archive(fake, archive, options=opts, clock=lambda: now.timestamp()))
    assert [m.id for m in archive.load_messages(1)] == [1, 2]  # saved before the interruption

    seen: list[int] = []

    async def recording(entity: str, **kw: Any):
        async for m in original(entity, **kw):
            seen.append(m.id)
            yield m

    fake.iter_messages = recording
    asyncio.run(tg.sync_archive(fake, archive, options=opts, clock=lambda: now.timestamp()))
    assert seen == [3, 4, 5]  # resumed after 2: nothing fetched twice
    assert [m.id for m in archive.load_messages(1)] == [1, 2, 3, 4, 5]
