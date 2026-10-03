"""At-rest encryption for the source secrets entered through Settings.

Ciphertext lives in one place: each source's `secrets` column. The Settings UI never gets a value back — only whether one is set and a
last-four preview.

Where the key lives decides what encryption is worth:

  NETMAP_SECRET_KEY set   the key is in docker-compose.yml, the database holds
                          only ciphertext — a copy of netmap.db on its own
                          (a backup, a support bundle) cannot be decrypted.
  not set                 a key generated on first boot is stored in the
                          database. Anyone with the file can decrypt; this only
                          keeps secrets out of plain sight in a SQL dump.

Setting NETMAP_SECRET_KEY on an installation that started without it is a
migration, done at start-up by `sources.rotate_secrets()`: everything is
re-encrypted with the new key and the stored key is then deleted. The stored
key is kept only while some secret still needs it.

Before 1.69.8 a key that did not match simply made every secret decrypt to "",
so sources went quiet as if never configured. A secret no known key opens is
now counted, logged at start-up and raised on the Overview.
"""
import os

from cryptography.fernet import Fernet, InvalidToken, MultiFernet

from . import db

_KEY_NAME = "source_secret_key"
_fernet: MultiFernet | None = None

# Filled in by sources.rotate_secrets() at start-up: where a stored secret
# could not be decrypted with any known key, as "<source>.<field>".
UNDECRYPTABLE: list[str] = []


def _env_key() -> str:
    return os.environ.get("NETMAP_SECRET_KEY", "").strip()


def _keys() -> list[str]:
    """Encrypt with the first, decrypt with any."""
    env, stored = _env_key(), db.get_setting(_KEY_NAME)
    if env:
        try:
            Fernet(env.encode())
        except Exception:
            raise SystemExit("[netmap] FATAL: NETMAP_SECRET_KEY is not a valid Fernet key "
                             "(32 url-safe base64-encoded bytes). Generate one with: "
                             "python3 -c \"from cryptography.fernet import Fernet; "
                             "print(Fernet.generate_key().decode())\"")
        return [env] + ([stored] if stored and stored != env else [])
    if not stored:
        stored = Fernet.generate_key().decode()
        db.set_setting(_KEY_NAME, stored)
    return [stored]


def _f() -> MultiFernet:
    global _fernet
    if _fernet is None:
        _fernet = MultiFernet([Fernet(k.encode()) for k in _keys()])
    return _fernet


def reset() -> None:
    """Forget the loaded keys (after the stored key is deleted, and in tests)."""
    global _fernet
    _fernet = None


def key_location() -> str:
    """For Settings > About: 'environment' or 'database'."""
    return "environment" if _env_key() else "database"


def encrypt(plaintext: str) -> str:
    if not plaintext:
        return ""
    return _f().encrypt(plaintext.encode()).decode()


def decrypt(token: str) -> str:
    if not token:
        return ""
    try:
        return _f().decrypt(token.encode()).decode()
    except InvalidToken:
        # Reported at start-up by rotate_secrets(); here a scan just sees an
        # unset field rather than crashing.
        return ""


def rotate(token: str) -> str | None:
    """The token re-encrypted with the current key, or None if no known key
    opens it."""
    if not token:
        return token
    primary = Fernet(_keys()[0].encode())
    try:
        primary.decrypt(token.encode())
        return token            # already under the current key — leave it be
    except InvalidToken:
        pass
    try:
        return _f().rotate(token.encode()).decode()
    except InvalidToken:
        return None


def needs_stored_key() -> bool:
    """True while the database key is still the one encrypting."""
    return not _env_key()


def forget_stored_key() -> bool:
    """Delete the database copy of the key. Only valid once every secret has
    been re-encrypted with NETMAP_SECRET_KEY."""
    if not _env_key() or db.get_setting(_KEY_NAME) is None:
        return False
    db.delete_setting(_KEY_NAME)
    reset()
    return True


MASK_MIN = 16      # shorter than this, not even the last four are shown


def mask(plaintext: str) -> str:
    """For the Settings list: a fixed row of dots, and the last four
    characters of a long token — enough to tell two tokens apart, never
    enough to reuse. Neither the length nor any part of a short secret (a
    password) is shown: four characters of a six-character password is most
    of it."""
    if not plaintext:
        return ""
    return "•" * 8 + (plaintext[-4:] if len(plaintext) >= MASK_MIN else "")
