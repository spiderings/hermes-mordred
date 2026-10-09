"""Read-only Telegram import for the extension server.

Imports the operator's own Telegram account (MTProto user session, via
Telethon) into an encrypted local archive and answers questions over it with a
Venice.ai private model. See ``docs/dev/SPEC.md`` §"Telegram import" for the
threat model. Telethon is optional: ``pip install 'hermes-mordred[telegram]'``.
"""
