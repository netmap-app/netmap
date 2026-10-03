"""The settings form every source driver declares, and how its values are read.

A driver's `FIELDS` is a list of:

    key          the cfg key the driver reads
    label        the Settings form label
    type         text | number | password | checkbox
    secret       encrypted at rest, never handed back (password fields)
    required     must be set before the instance can be saved
    default      used when the stored value is missing or blank
    integer      a number field that is a whole number
    wide         a wider input (URLs, tokens)
    placeholder  hint text
    binds        what a secret was entered *for* — changing it without
                 re-entering the secret is refused, so a stored credential is
                 never sent to an address or user it was not entered for
    env          the environment variable this field was read from before
                 1.75.0 — used only by the one-time seed, see
                 sources.migrate_legacy()

Values are cast here once, when saved, and again when handed to a driver, so a
driver's `cfg` always holds a bool for a checkbox and a number for a number —
never the string "false" that used to switch a flag on.
"""
import ssl


def as_bool(v) -> bool:
    """A checkbox value from a form, JSON, an environment variable or storage.
    `bool("false")` is True, which is how "false" used to switch a flag on."""
    if isinstance(v, bool):
        return v
    if isinstance(v, (int, float)) and v in (0, 1):
        return bool(v)
    s = str(v).strip().lower()
    if s in ("1", "true", "yes", "on"):
        return True
    if s in ("0", "false", "no", "off", ""):
        return False
    raise ValueError(f"{v!r} is not a yes/no value")


def cast(f: dict, raw):
    """One value, as its field's type. Raises ValueError with a message fit for
    the Settings form."""
    t = f.get("type", "text")
    if t == "checkbox":
        try:
            return as_bool(raw)
        except ValueError:
            raise ValueError(f"'{f['key']}' must be a yes/no value") from None
    if t == "number":
        s = str(raw).strip()
        try:
            return int(float(s)) if f.get("integer") else float(s)
        except ValueError:
            kind = "whole number" if f.get("integer") else "number"
            raise ValueError(f"'{f['key']}' must be a {kind}") from None
    s = "" if raw is None else str(raw)
    # URLs lose surrounding space and a trailing slash — "http://x/" + "/api"
    # is "//api". Secrets are left exactly as typed: a trailing space in a
    # password is the password.
    return s.strip().rstrip("/") if f["key"] == "url" else s


def blank(v) -> bool:
    return v is None or (isinstance(v, str) and v.strip() == "")


def coerce(field_defs: list[dict], raw: dict) -> dict:
    """Stored config + decrypted secrets → what a driver reads: every field
    present, typed, blanks replaced by defaults. A value that no longer casts
    (stored before a field changed type) falls back to the default rather than
    stopping the scan."""
    out = {}
    for f in field_defs:
        v = raw.get(f["key"])
        if blank(v) and f.get("type") != "checkbox":
            v = f.get("default", "")
        elif v is None:
            v = f.get("default", False)
        try:
            out[f["key"]] = cast(f, v) if not blank(v) or f.get("type") == "checkbox" else v
        except ValueError:
            out[f["key"]] = f.get("default", "")
    return out


def split(field_defs: list[dict], fields_in: dict) -> tuple[dict, dict]:
    """A form submission into (config, secrets), using the field list to decide
    which is which — so a caller cannot write a token into a plaintext column —
    and casting every value, so a bad one is refused on save rather than
    breaking a scan later. Secrets come back in plaintext for the caller to
    encrypt; a blank one is left out, which means "keep what is stored"."""
    defs = {f["key"]: f for f in field_defs}
    config, secrets = {}, {}
    for key, val in (fields_in or {}).items():
        f = defs.get(key)
        if not f:
            continue
        if f.get("secret"):
            if not blank(val):
                secrets[key] = str(val)
        elif blank(val) and f.get("type") != "checkbox":
            config[key] = ""           # blank means "use the default"
        else:
            config[key] = cast(f, val)
    return config, secrets


def require(field_defs: list[dict], config: dict, secret_keys) -> None:
    """Refuse a save that leaves a required field empty."""
    missing = [f["label"] for f in field_defs if f.get("required")
               and (blank(config.get(f["key"])) if not f.get("secret")
                    else f["key"] not in secret_keys)]
    if missing:
        raise ValueError(f"{', '.join(missing)} {'is' if len(missing) == 1 else 'are'} required")


def check_rebind(field_defs: list[dict], before: dict, config: dict, secrets: dict) -> None:
    """A stored secret is never carried over to an address or identity it was
    not entered for: changing a `binds` field needs every stored secret typed
    again. `before` is the stored row ({config, secrets})."""
    rebound = [f["label"] for f in field_defs if f.get("binds") and f["key"] in config
               and str(config[f["key"]]).strip().rstrip("/")
               != str(before["config"].get(f["key"], "")).strip().rstrip("/")]
    missing = [f["label"] for f in field_defs if f.get("secret")
               and before["secrets"].get(f["key"]) and f["key"] not in secrets]
    if rebound and missing:
        raise ValueError(
            f"changing {', '.join(rebound)} needs {', '.join(missing)} "
            "entered again — a stored secret is never sent to an address "
            "or user it was not entered for")


def tls(cfg: dict):
    """The SSL context for a driver's `verify_ssl` field: None verifies."""
    if cfg.get("verify_ssl", True):
        return None
    c = ssl.create_default_context()
    c.check_hostname = False
    c.verify_mode = ssl.CERT_NONE
    return c
