import hashlib
import hmac
import secrets
from dataclasses import dataclass
from datetime import datetime

from sqlalchemy import Connection, func, insert, select, update

from pen16.db import TokenKind, tokens


@dataclass(frozen=True)
class Token:
    """A token as `pen16 tokens` lists it: never its secret, which only its hash records."""

    id: str
    kind: TokenKind
    name: str
    created_at: datetime
    last_used_at: datetime | None
    revoked_at: datetime | None


def create(conn: Connection, kind: TokenKind, name: str) -> str:
    """Create a token and return it. Only its hash is stored, so this is the one chance to see it."""
    token_id = secrets.token_hex(4)
    secret = secrets.token_urlsafe(32)
    conn.execute(insert(tokens).values(id=token_id, kind=kind, name=name, secret_hash=_hash(secret)))
    return f"pen16_{token_id}_{secret}"


def verify(conn: Connection, presented: str, kind: TokenKind) -> str | None:
    """Return the token's ID if it's a live token of this kind, and record that it was used."""
    prefix, _, rest = presented.partition("_")
    token_id, _, secret = rest.partition("_")
    if prefix != "pen16" or not secret:
        return None
    stored = conn.scalar(
        select(tokens.c.secret_hash).where(
            tokens.c.id == token_id, tokens.c.kind == kind, tokens.c.revoked_at.is_(None)
        )
    )
    if stored is None or not hmac.compare_digest(stored, _hash(secret)):
        return None
    conn.execute(update(tokens).where(tokens.c.id == token_id).values(last_used_at=func.now()))
    return token_id


def name(conn: Connection, token_id: str) -> str:
    """The name a token was created with: for a compliance token, the host it speaks for."""
    return str(conn.scalar(select(tokens.c.name).where(tokens.c.id == token_id)))


def listed(conn: Connection) -> list[Token]:
    """Every token, revoked ones included, oldest first."""
    rows = conn.execute(
        select(
            tokens.c.id,
            tokens.c.kind,
            tokens.c.name,
            tokens.c.created_at,
            tokens.c.last_used_at,
            tokens.c.revoked_at,
        ).order_by(tokens.c.created_at)
    )
    return [
        Token(row.id, TokenKind(row.kind), row.name, row.created_at, row.last_used_at, row.revoked_at)
        for row in rows
    ]


def revoke(conn: Connection, token_id: str) -> None:
    """Revoke a live token. The next request that presents it is refused."""
    revoked = conn.scalar(
        update(tokens)
        .where(tokens.c.id == token_id, tokens.c.revoked_at.is_(None))
        .values(revoked_at=func.now())
        .returning(tokens.c.id)
    )
    if revoked is None:
        raise LookupError(f"no live token {token_id!r} (pen16 tokens lists them)")


def _hash(secret: str) -> str:
    return hashlib.sha256(secret.encode()).hexdigest()
