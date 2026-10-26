import hashlib
import hmac
import secrets

from sqlalchemy import Connection, func, insert, select, update

from pen16.db import tokens


def create(conn: Connection, kind: str, name: str) -> str:
    """Create a token and return it. Only its hash is stored, so this is the one chance to see it."""
    token_id = secrets.token_hex(4)
    secret = secrets.token_urlsafe(32)
    conn.execute(insert(tokens).values(id=token_id, kind=kind, name=name, secret_hash=_hash(secret)))
    return f"pen16_{token_id}_{secret}"


def verify(conn: Connection, presented: str, kind: str) -> str | None:
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


def revoke(conn: Connection, token_id: str) -> None:
    conn.execute(update(tokens).where(tokens.c.id == token_id).values(revoked_at=func.now()))


def _hash(secret: str) -> str:
    return hashlib.sha256(secret.encode()).hexdigest()
