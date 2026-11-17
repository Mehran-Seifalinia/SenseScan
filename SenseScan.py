#!/usr/bin/env python3
"""Sensitive data scanner for source files, text files, PDFs and image metadata."""

from argparse import ArgumentParser, ArgumentTypeError, Namespace
from base64 import b64decode
from bisect import bisect_right
from dataclasses import dataclass, field
from datetime import datetime, timezone
from hashlib import sha256
from html import escape as html_escape
from ipaddress import ip_address
from json import dumps as json_dumps
from os import environ as os_environ, getcwd as os_getcwd, walk as os_walk
from pathlib import Path
from re import (
    IGNORECASE as re_IGNORECASE,
    MULTILINE as re_MULTILINE,
    Match as re_Match,
    Pattern as re_Pattern,
    compile as re_compile,
    escape as re_escape,
)
from sys import (
    argv as sys_argv,
    exit as sys_exit,
    platform as sys_platform,
    stderr as sys_stderr,
    stdout as sys_stdout,
    version_info as sys_version_info,
)
from textwrap import wrap as text_wrap
from time import perf_counter as time_perf_counter
from traceback import format_exc as traceback_format_exc
from typing import Any, Callable
from zipfile import ZipFile

# Optional dependencies: the tool still runs without them and warns once.
try:
    from pypdf import PdfReader as _PdfReader
    _HAS_PYPDF = True
except ImportError:
    _PdfReader = None
    _HAS_PYPDF = False

try:
    from PIL import ExifTags as _PILExifTags, Image as _PILImage
    _HAS_PIL = True
except ImportError:
    _PILExifTags = None
    _PILImage = None
    _HAS_PIL = False

# ExifTags.IFD was introduced in Pillow 9.4.0. Older versions only expose
# the numeric tags (Exif = 0x8769, GPSInfo = 0x8825). Fall back to the
# numbers so extraction keeps working on older Pillow.
if _PILExifTags is not None and hasattr(_PILExifTags, "IFD"):
    _EXIF_IFD = _PILExifTags.IFD.Exif
    _GPS_INFO_IFD = _PILExifTags.IFD.GPSInfo
else:
    _EXIF_IFD = 0x8769
    _GPS_INFO_IFD = 0x8825

try:
    from colorama import init as _colorama_init
    _HAS_COLORAMA = True
except ImportError:
    _colorama_init = None
    _HAS_COLORAMA = False

try:
    from ctypes import byref as _byref, c_ulong as _c_ulong, windll as _windll
    _HAS_WINDLL = True
except (ImportError, AttributeError):
    _byref = None
    _c_ulong = None
    _windll = None
    _HAS_WINDLL = False


TOOL_VERSION = "2.0.0"

EXIT_SUCCESS = 0
EXIT_FINDINGS = 1
EXIT_ERROR = 2
EXIT_NO_FILES = 3
EXIT_INTERRUPTED = 130

# Build output folders (dist, build, ...) are intentionally NOT excluded:
# bundled JS is exactly where leaked secrets usually end up.
DEFAULT_EXCLUDES = frozenset({
    ".git", "node_modules", ".venv", "venv", "__pycache__",
    ".idea", ".vscode", "coverage", ".pytest_cache", ".mypy_cache",
    ".tox", ".cache", ".gradle", ".mvn", ".parcel-cache",
})

TEXT_EXTENSIONS = frozenset({
    ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".vue", ".svelte",
    ".py", ".pyi", ".java", ".kt", ".scala", ".go", ".rs", ".rb", ".php",
    ".c", ".h", ".cpp", ".hpp", ".cc", ".cs", ".swift", ".m", ".mm",
    ".html", ".htm", ".css", ".scss", ".sass", ".less",
    ".json", ".yml", ".yaml", ".toml", ".ini", ".cfg", ".conf",
    ".xml", ".svg", ".md", ".txt", ".log", ".sql", ".map",
    ".sh", ".bash", ".zsh", ".ps1", ".bat", ".cmd",
    ".env", ".lock", ".gitignore", ".gitattributes", ".editorconfig",
    ".properties", ".gradle", ".dockerfile", ".makefile",
})

# Compressed containers are never opened; they are skipped silently.
ARCHIVE_EXTENSIONS = frozenset({
    ".zip", ".tar", ".gz", ".tgz", ".bz2", ".xz", ".7z", ".rar",
    ".jar", ".war", ".ear", ".apk", ".ipa", ".whl", ".egg",
})

# Images are never content-scanned (no OCR); only their metadata is inspected.
IMAGE_EXTENSIONS = frozenset({
    ".jpg", ".jpeg", ".png", ".gif", ".bmp", ".webp", ".tif", ".tiff",
    ".heic", ".heif", ".ico",
})
IMAGE_MAGIC = (
    b"\x89PNG",           # PNG
    b"\xff\xd8\xff",      # JPEG
    b"GIF8",              # GIF87a / GIF89a
    b"II*\x00",           # TIFF little-endian
    b"MM\x00*",           # TIFF big-endian
    b"\x00\x00\x01\x00",  # ICO
    b"\x00\x00\x02\x00",  # CUR
)

_WEBP_RIFF = b"RIFF"
_WEBP_BRAND = b"WEBP"
_HEIF_BOX = b"ftyp"
_HEIF_BRANDS = frozenset({
    b"heic", b"heix", b"hevc", b"hevx",
    b"heim", b"heis", b"hevm", b"hevs",
    b"mif1", b"msf1",
})
_BMP_DIB_SIZES = frozenset({12, 40, 52, 56, 64, 108, 124})


def _is_bmp(head: bytes) -> bool:
    # A bare "BM" prefix would false-positive on text files such as
    # "BMW ..." — require a valid DIB header size at offset 14.
    if len(head) < 18 or head[:2] != b"BM":
        return False
    return int.from_bytes(head[14:18], "little") in _BMP_DIB_SIZES

PDF_EXTENSIONS = frozenset({".pdf"})
OFFICE_EXTENSIONS = frozenset({".docx", ".xlsx", ".pptx", ".odt", ".ods", ".odp"})

CATEGORY_ORDER = (
    "credentials", "tokens", "private_keys", "database",
    "usernames", "emails", "phone_numbers", "ips",
    "urls", "files", "paths_internal", "paths_system",
    "api_endpoints_complete", "api_endpoints_partial",
    "errors", "technology", "infrastructure",
    "env_vars", "storage", "metadata", "other",
)
ALL_CATEGORIES = frozenset(CATEGORY_ORDER)
HIGH_SEVERITY = frozenset({"credentials", "tokens", "private_keys", "database"})

# Match printable Unicode: exclude C0/C1 control chars, include tabs
PRINTABLE_RE = re_compile(rb"[^\x00-\x1f\x7f-\x9f]{6,}")
MAX_OFFICE_ENTRY = 64 * 1024 * 1024
MAX_OFFICE_TOTAL = 256 * 1024 * 1024
DEFAULT_MAX_SIZE = 50 * 1024 ** 2  # 50 MB

# Metadata keys (lowercased) that are reported as findings on their own.
SENSITIVE_META_KEYS = frozenset({
    "author", "creator", "producer", "subject", "keywords", "artist",
    "copyright", "software", "make", "model", "hostcomputer", "ownername",
    "cameraownername", "bodyserialnumber", "lensserialnumber", "imageuniqueid",
    "usercomment", "imagedescription", "xpauthor", "xpcomment", "xpkeywords",
    "xpsubject", "documentname", "datetimeoriginal", "datetime", "comment",
    "description", "source", "lastmodifiedby", "company", "manager",
    "application", "appversion", "initial-creator", "generator",
    "creation-date", "creationdate", "moddate", "created", "modified", "xmp",
})

NOISE_URL_HOSTS = frozenset({
    "w3.org", "schemas.xmlsoap.org", "ns.adobe.com", "purl.org",
    "xml.org", "xmlns.com", "json-schema.org", "schema.org",
})

NON_EMAIL_TLDS = frozenset({
    "png", "jpg", "jpeg", "gif", "svg", "webp", "css", "js", "json",
    "woff", "woff2", "ttf", "eot", "map", "html", "ico", "mp4", "webm",
})

USERNAME_NOISE = frozenset({
    "any", "unknown", "void", "never", "object", "user", "users", "self", "this",
})

PLACEHOLDER_VALUES = frozenset({
    "", "null", "none", "nil", "undefined", "true", "false", "nan",
    "here", "your_password_here", "your_password", "your_api_key",
    "your_secret", "your_token", "your_key", "your_key_here",
    "your-token-here", "your-secret-here", "your-key-here",
    "password", "passwd", "pwd", "changeme", "change_me", "change-me",
    "example", "sample", "dummy", "placeholder", "insert_here",
    "enter_your", "your_api_key_here", "todo", "fixme", "test",
    "testing", "fake", "mock", "demo", "xxx", "xxxxxx",
    "******", "***", "...", "???", "<password>", "<secret>",
    "<token>", "<your-key>", "<api-key>", "n/a", "na", "empty",
    "string", "integer", "boolean", "object", "array",
    "bool", "float", "bytes", "byte", "bytearray", "dict", "list",
    "tuple", "frozenset", "long", "short", "double", "char", "date",
    "number", "bigint", "symbol", "void", "unknown", "never",
    "uuid", "optional", "union",
})

PLACEHOLDER_EMAILS = frozenset({
    "user@example.com", "example@example.com", "test@test.com",
    "email@example.com", "name@example.com", "you@example.com",
    "user@domain.com", "admin@example.com", "info@example.com",
    "noreply@example.com", "no-reply@example.com", "user@example.org",
    "user@example.net", "someone@example.com", "user@localhost",
})

PLACEHOLDER_EMAIL_DOMAINS = frozenset({
    "example.com", "example.org", "example.net", "example.edu",
    "test.com", "test.org", "test.net", "test.local", "test",
    "domain.com", "domain.org", "domain.net", "localhost",
    "email.com", "email.org", "mail.local",
})


class Colors:
    enabled: bool = True

    @classmethod
    def paint(cls, code: str, text: str) -> str:
        return f"\033[{code}m{text}\033[0m" if cls.enabled else text

    @classmethod
    def red(cls, t: str) -> str:
        return cls.paint("31", t)

    @classmethod
    def green(cls, t: str) -> str:
        return cls.paint("32", t)

    @classmethod
    def yellow(cls, t: str) -> str:
        return cls.paint("33", t)

    @classmethod
    def blue(cls, t: str) -> str:
        return cls.paint("34", t)

    @classmethod
    def cyan(cls, t: str) -> str:
        return cls.paint("36", t)

    @classmethod
    def dim(cls, t: str) -> str:
        return cls.paint("2", t)


def init_colors(no_color: bool = False) -> None:
    if no_color or os_environ.get("NO_COLOR"):
        Colors.enabled = False
        return
    if sys_platform == "win32":
        # Windows consoles need ANSI processing switched on explicitly.
        if _HAS_COLORAMA:
            try:
                _colorama_init()
                Colors.enabled = True
                return
            except Exception:
                pass
        if _HAS_WINDLL:
            try:
                handle = _windll.kernel32.GetStdHandle(-11)
                mode = _c_ulong()
                if _windll.kernel32.GetConsoleMode(handle, _byref(mode)):
                    _windll.kernel32.SetConsoleMode(handle, mode.value | 0x0004)
                    Colors.enabled = True
                    return
            except Exception:
                pass
        Colors.enabled = False
    else:
        try:
            Colors.enabled = bool(sys_stdout.isatty())
        except Exception:
            Colors.enabled = False


@dataclass(frozen=True, slots=True)
class PatternSpec:
    category: str
    type: str
    regex: re_Pattern[str]
    validator: Callable[[str], bool] | None = None
    capture_groups: tuple[int, ...] = (1,)
    # When set, the HTTP method found in this group is prefixed to the value.
    method_group: int = 0
    # Fallback method when method_group is set but did not match
    # (e.g. fetch() without an explicit method implies GET).
    default_method: str = ""


@dataclass(slots=True)
class Finding:
    category: str
    type: str
    value: str
    file: str
    line: int
    column: int
    preview: str = ""
    source: str = "content"


@dataclass(slots=True)
class FileResult:
    path: str
    size: int
    kind: str
    findings: list[Finding]
    errors: list[str]
    duration_ms: float
    patterns_checked: int
    skipped_reason: str | None = None


@dataclass(slots=True)
class ScanReport:
    base_path: str = ""
    started_at: str = ""
    duration_sec: float = 0.0
    scanned_files: int = 0
    skipped_files: int = 0
    findings: list[Finding] = field(default_factory=list)
    skipped_large: list[tuple[str, int]] = field(default_factory=list)
    duplicate_files: list[tuple[str, str]] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    file_results: list[FileResult] = field(default_factory=list)
    excluded_categories: list[str] = field(default_factory=list)
    excluded_patterns: list[str] = field(default_factory=list)
    options: dict[str, Any] = field(default_factory=dict)


# ───────────────────────── validators ─────────────────────────

def is_valid_value(value: str, min_len: int = 3) -> bool:
    v = value.strip().strip("'\"`")
    if len(v) < min_len:
        return False
    if v.lower() in PLACEHOLDER_VALUES:
        return False
    if v.startswith(("${", "{{", "<%", "process.env", "import.meta.env",
                     "os.environ", "getenv(", "%(")):
        return False
    if any(marker in v for marker in ("${", "{{", "<%")):
        return False
    low = v.lower()
    if low.startswith(("your_", "example_", "sample_", "dummy_", "test_")):
        return False
    if low.endswith(("_here", "_placeholder", "_example", "_sample")):
        return False
    if len(set(v)) == 1:
        return False
    return v not in ("True", "False", "None", "NULL", "NULLPTR")


# Identifier-like values (req.body.password, userPassword) are code, not secrets.
CODE_REFERENCE_RE = re_compile(
    r"^[A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)+$"
    r"|^[a-z]+(?:[A-Z][a-z0-9]+)+$"
)
_COMMENT_PREFIX_RE = re_compile(r"^[ \t]*(?:#|//|/\*)")
_COMMENT_FILTER_TYPES = frozenset({"password_unquoted", "username_unquoted"})

def looks_like_code(value: str) -> bool:
    return bool(CODE_REFERENCE_RE.match(value.strip().strip("'\"`")))


def is_valid_secret(value: str) -> bool:
    v = value.strip().strip("'\"`")
    if not is_valid_value(v):
        return False
    if any(c.isspace() for c in v):
        return False
    if v.startswith(("/", "./", "../", "http://", "https://")):
        return False
    return not looks_like_code(v)


def is_valid_plain_secret(value: str) -> bool:
    v = value.strip()
    if not is_valid_value(v):
        return False
    if v.startswith(("$", "@", "*", "!", "&")):
        return False
    return not looks_like_code(v)


def is_valid_env_secret(value: str) -> bool:
    v = value.strip()
    if not is_valid_value(v):
        return False
    if v.startswith(("$", "@", "*", "&")):
        return False
    return not looks_like_code(v)


def is_basic_auth(value: str) -> bool:
    # A real Basic header decodes to "user:password"; ordinary words do not.
    try:
        raw = b64decode(value + "=" * (-len(value) % 4), validate=True)
    except Exception:
        return False
    return b":" in raw


def is_valid_token(value: str) -> bool:
    v = value.strip().strip("'\"`")
    if not v or len(v) < 8:
        return False
    low = v.lower()
    if low.startswith(("your_", "your-")) or any(
        m in low for m in ("example", "sample", "placeholder", "dummy", "fake")
    ):
        return False
    alnum = [c for c in v if c.isalnum()]
    if not alnum:
        return False
    counts: dict[str, int] = {}
    for c in alnum:
        counts[c] = counts.get(c, 0) + 1
    return max(counts.values()) / len(alnum) <= 0.6


def is_valid_secret_token(value: str) -> bool:
    return is_valid_secret(value) and is_valid_token(value)


def is_valid_email(value: str) -> bool:
    v = value.strip().lower()
    if v in PLACEHOLDER_EMAILS:
        return False
    if "@" not in v or v.count("@") != 1:
        return False
    local, _, domain = v.partition("@")
    if not local or not domain or "." not in domain:
        return False
    for bad in PLACEHOLDER_EMAIL_DOMAINS:
        if domain == bad or domain.endswith("." + bad):
            return False
    if len(v) > 254 or len(local) > 64:
        return False
    if domain.startswith(".") or domain.endswith(".") or ".." in v:
        return False
    if any(c in v for c in " \t\r\n()[]{}<>,;:"):
        return False
    tld = domain.rsplit(".", 1)[-1]
    return len(tld) >= 2 and tld.isalpha() and tld not in NON_EMAIL_TLDS


def is_valid_username(value: str) -> bool:
    v = value.strip()
    if not is_valid_value(v, min_len=2):
        return False
    if v.isdigit():
        return False
    if any(c in v for c in " \t\r\n{}\"'`"):
        return False
    if v.upper() in ("GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"):
        return False
    if v.startswith(("/", ".")) or v.lower() in USERNAME_NOISE:
        return False
    return not looks_like_code(v)


def is_valid_plain_username(value: str) -> bool:
    return is_valid_username(value) and not looks_like_code(value)


def is_valid_url(value: str) -> bool:
    v = value.strip().rstrip(".,;:)]}'\"")
    if not v.startswith(("http://", "https://")):
        return False
    if len(v) < 10 or len(v) > 2048:
        return False
    if any(c in v for c in " \t\r\n\"'<>"):
        return False
    rest = v.split("://", 1)[1]
    if not rest or rest.startswith("/"):
        return False
    authority = rest.split("/", 1)[0].split("?", 1)[0].split("#", 1)[0]
    host = authority.rsplit("@", 1)[-1].split(":")[0].lower()
    if not host or host.startswith(".") or host.endswith("."):
        return False
    return not any(host == n or host.endswith("." + n) for n in NOISE_URL_HOSTS)


def is_valid_ip(value: str) -> bool:
    v = value.strip()
    try:
        ip_address(v)
    except ValueError:
        return False
    # Only the IPv4 broadcast address is rejected. Loopback, unspecified,
    # private and IPv6 loopback addresses are kept: they frequently reveal
    # internal services, dev servers and misconfigured backends.
    return v != "255.255.255.255"


_SYSTEM_PREFIXES = (
    "/etc/", "/usr/", "/var/", "/home/", "/root/", "/opt/", "/tmp/",
    "/bin/", "/sbin/", "/lib/", "/boot/", "/dev/", "/proc/", "/sys/",
    "/mnt/", "/media/", "/srv/", "/run/", "/snap/", "/private/", "/Volumes/",
)
_API_LIKE_RE = re_compile(r"(?:^|/)(?:api|rest|graphql|v\d+)(?:/|$)")


def is_internal_route(value: str) -> bool:
    return not value.startswith(_SYSTEM_PREFIXES) and not _API_LIKE_RE.search(value)


def is_sensitive_env_name(name: str) -> bool:
    upper = name.upper()
    return any(kw in upper for kw in (
        "PASSWORD", "PASSWD", "SECRET", "KEY", "TOKEN", "CREDENTIAL",
        "AUTH", "PRIVATE", "DATABASE", "DB_", "MONGO", "REDIS",
        "MYSQL", "POSTGRES", "AWS", "AZURE", "GCP", "SMTP", "MAIL",
        "STRIPE", "PAYPAL", "TWILIO", "SENDGRID", "SLACK", "GITHUB",
        "GITLAB", "NPM", "PYPI", "JWT", "SESSION",
    ))


# ───────────────────────── patterns ─────────────────────────

# Separator between a key and its value: optional closing quote of the key,
# then ":", ":=", "=", "==", "===", "!=" or "!==" (JSON, YAML, JS, comparisons).
_ASSIGN = r"""["'`]?\s*(?::=|:|=)\s*"""

_TECHS = (
    "react", "react-dom", "vue", "angular", "svelte", "jquery",
    "jquery-ui", "bootstrap", "tailwindcss", "lodash", "axios",
    "moment", "dayjs", "chart.js", "express", "next", "nuxt",
    "koa", "fastify", "hapi", "typescript", "webpack", "vite",
    "babel", "rollup", "esbuild", "parcel", "redux", "mobx",
    "zustand", "recoil", "graphql", "socket.io", "three", "d3",
    "jest", "mocha", "cypress", "playwright", "vitest",
    "eslint", "prettier", "stripe", "firebase", "supabase",
    "auth0", "mysql", "mysql2", "pg", "mongodb", "mongoose",
    "redis", "sqlite3", "sequelize", "typeorm", "prisma",
    "node", "django", "flask", "fastapi", "spring", "hibernate",
    "laravel", "symfony", "rails", "wordpress", "drupal",
)


def _tech_id(name: str) -> str:
    return name.replace("/", "_").replace("@", "").replace(".", "_")

_NON_SECRET_ENV_SUFFIX = (
    r"(?:_URL|_URI|_HOST|_PORT|_TIMEOUT|_TTL|_EXPIRY|_INTERVAL|_SIZE"
    r"|_LIMIT|_COUNT|_LEVEL|_MODE|_TYPE|_NAME|_PATH|_DIR|_ENABLED"
    r"|_LENGTH|_FORMAT|_VERSION|_ENV|_REGION|_ZONE|_PREFIX|_SUFFIX"
    r"|_METHOD|_PROTOCOL|_HEADER|_ATTEMPTS|_RETRIES|_DELAY|_BUFFER"
    r"|_CHUNK|_THRESHOLD|_RATIO|_WEIGHT|_ALGORITHM)"
)

def build_patterns() -> list[PatternSpec]:
    specs: list[PatternSpec] = []
    add = specs.append

    # ── tokens ──
    add(PatternSpec("tokens", "aws_access_key",
        re_compile(r"\b((?:AKIA|ASIA)[0-9A-Z]{16})\b"), validator=is_valid_token))
    add(PatternSpec("tokens", "aws_secret_key",
        re_compile(r"""(?i)aws_?secret_?access_?key["'`]?\s*[:=]\s*["'`]?([A-Za-z0-9/+=]{40})(?![A-Za-z0-9/+=])"""),
        validator=is_valid_token))
    add(PatternSpec("tokens", "aws_session_token",
        re_compile(r"""(?i)aws_?session_?token["'`]?\s*[:=]\s*["'`]?([A-Za-z0-9/+=]{100,})"""),
        validator=is_valid_token))
    add(PatternSpec("tokens", "gcp_api_key",
        re_compile(r"\b(AIza[0-9A-Za-z_\-]{35})\b"), validator=is_valid_token))
    add(PatternSpec("tokens", "gcp_service_account",
        re_compile(r'("type"\s*:\s*"service_account")')))
    add(PatternSpec("tokens", "github_token",
        re_compile(r"\b(gh[pousr]_[A-Za-z0-9]{36,251})\b"), validator=is_valid_token))
    add(PatternSpec("tokens", "gitlab_token",
        re_compile(r"\b(glpat-[A-Za-z0-9_\-]{20,})"), validator=is_valid_token))
    add(PatternSpec("tokens", "slack_token",
        re_compile(r"\b(xox[baprs]-[A-Za-z0-9\-]{10,})"), validator=is_valid_token))
    add(PatternSpec("tokens", "slack_webhook",
        re_compile(r"(https://hooks\.slack\.com/services/[A-Za-z0-9/]+)"), validator=is_valid_token))
    add(PatternSpec("tokens", "stripe_key",
        re_compile(r"\b((?:sk|pk|rk)_(?:live|test)_[A-Za-z0-9]{20,})"), validator=is_valid_token))
    add(PatternSpec("tokens", "sendgrid_key",
        re_compile(r"\b(SG\.[A-Za-z0-9_\-]{22,}\.[A-Za-z0-9_\-]{22,})"), validator=is_valid_token))
    add(PatternSpec("tokens", "twilio_key",
        re_compile(r"\b(SK[0-9a-fA-F]{32})\b"), validator=is_valid_token))
    add(PatternSpec("tokens", "mailgun_key",
        re_compile(r"\b(key-[0-9a-f]{32})\b"), validator=is_valid_token))
    add(PatternSpec("tokens", "npm_token",
        re_compile(r"\b(npm_[A-Za-z0-9]{36})\b"), validator=is_valid_token))
    add(PatternSpec("tokens", "pypi_token",
        re_compile(r"\b(pypi-AgEIcHlwaS5vcmc[A-Za-z0-9_\-]{50,})\b"), validator=is_valid_token))
    add(PatternSpec("tokens", "digitalocean_token",
        re_compile(r"\b(dop_v1_[a-f0-9]{64})\b"), validator=is_valid_token))
    add(PatternSpec("tokens", "heroku_key",
        re_compile(r"""(?i)heroku\w*key["'`]?\s*[:=]\s*["'`]?([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})"""),
        validator=is_valid_token))
    add(PatternSpec("tokens", "jwt",
        re_compile(r"\b(eyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,})\b"),
        validator=is_valid_token))
    add(PatternSpec("tokens", "bearer_token",
        re_compile(r"""(?i)\bBearer\s+([A-Za-z0-9\-._~+/]{20,}=*)"""), validator=is_valid_token))
    add(PatternSpec("tokens", "basic_auth_header",
        re_compile(r"""(?i)\bBasic\s+([A-Za-z0-9+/]{16,}={0,2})"""),
        validator=is_basic_auth))
    add(PatternSpec("tokens", "discord_webhook",
        re_compile(r"(https://discord(?:app)?\.com/api/webhooks/\d+/[A-Za-z0-9_\-]+)"),
        validator=is_valid_token))
    add(PatternSpec("tokens", "telegram_bot_token",
        re_compile(r"\b(\d{8,10}:[A-Za-z0-9_\-]{35})\b"), validator=is_valid_token))
    add(PatternSpec("tokens", "generic_api_key",
        re_compile(
            r"(?i)(?:api[_-]?key|apikey|access[_-]?key|auth[_-]?token|"
            r"access[_-]?token|refresh[_-]?token|client[_-]?secret|"
            r"app[_-]?secret|auth[_-]?secret|secret[_-]?token)"
            + _ASSIGN + r"""["'`]([A-Za-z0-9_\-./+=]{8,512})["'`]"""
        ), validator=is_valid_secret_token))

    # ── private keys ──
    add(PatternSpec("private_keys", "private_key_header",
        re_compile(r"(-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED |)PRIVATE KEY(?: BLOCK)?-----)")))
    add(PatternSpec("private_keys", "certificate",
        re_compile(r"(-----BEGIN CERTIFICATE-----)")))

    # ── credentials ──
    add(PatternSpec("credentials", "url_credentials",
        re_compile(r"""(?i)\b[a-z][a-z0-9+.\-]*://([^:@\s/'"]+):([^@\s/'"]+)@"""),
        capture_groups=(2,), validator=is_valid_value))
    add(PatternSpec("credentials", "password_quoted",
        re_compile(
            r"(?i)(?:password|passwd|pwd|passphrase|secret[_-]?key|private[_-]?secret)"
            + _ASSIGN + r"""["'`]([^"'`\n\r]{3,256})["'`]"""
        ), validator=is_valid_secret))
    add(PatternSpec("credentials", "password_unquoted",
        re_compile(
            r"(?i)(?:password|passwd|secret[_-]?key|private[_-]?secret)" + _ASSIGN
            + r"""([^\s,'"`}{;()<>\[\]=][^\s,'"`}{;()<>\[\]]{3,255})"""
        ), validator=is_valid_plain_secret))
    add(PatternSpec("credentials", "env_secret",
        re_compile(
            r"""(?im)^[ \t]*(?:export[ \t]+)?"""
            r"""(?![A-Za-z0-9_]*""" + _NON_SECRET_ENV_SUFFIX + r"""[ \t]*=)"""
            r"""[A-Za-z0-9_]*"""
            r"""(?:SECRET|TOKEN|PASSWORD|PASSWD|API_?KEY|ACCESS_?KEY|PRIVATE_?KEY|CREDENTIALS?)"""
            r"""[A-Za-z0-9_]*[ \t]*=[ \t]*["']?([^\s"'#]{6,256})"""
        ), validator=is_valid_env_secret))
    add(PatternSpec("credentials", "jwt_secret",
        re_compile(
            r"(?i)(?:jwt[_-]?secret|jwt[_-]?key|signing[_-]?key|jwt[_-]?signing[_-]?secret)"
            + _ASSIGN + r"""["'`]([^"'`\n\r]{8,512})["'`]"""
        ), validator=is_valid_secret))
    add(PatternSpec("credentials", "commented_secret",
        re_compile(
            r"""(?i)(?://|#|/\*)\s*(?:password|passwd|pwd|secret|"""
            r"""api[_-]?key|token|username)\s*[:=]\s*["']?([^\s"'`*/]{3,256})"""
        ), validator=is_valid_value))
    add(PatternSpec("credentials", "connection_string",
        re_compile(
            r"(?i)(?:connection[_-]?string|conn[_-]?str)" + _ASSIGN
            + r"""["'`]([^"'`\n]{8,512})["'`]"""
        ), validator=is_valid_value))

    # ── usernames ──
    add(PatternSpec("usernames", "username",
        re_compile(
            r"(?i)(?<![a-z])(?:username|user_name|userid|user_id|user|login|account[_-]?name)"
            + _ASSIGN + r"""["'`]([^"'`\n\r]{2,128})["'`]"""
        ), validator=is_valid_username))
    add(PatternSpec("usernames", "username_unquoted",
        re_compile(
            r"""(?im)^[ \t]*(?:export[ \t]+)?(?:[\w.\-]*[_.\-])?"""
            r"""(?:username|user_name|user|login)[ \t]*[:=][ \t]*([^\s"'`#,;(){}\[\]<>]{2,128})"""
        ), validator=is_valid_plain_username))

    # ── emails / phones ──
    add(PatternSpec("emails", "email",
        re_compile(
            r"""(?<![\w.+-])([A-Za-z0-9][A-Za-z0-9._%+\-]{0,63}@"""
            r"""[A-Za-z0-9][A-Za-z0-9.\-]{0,253}\.[A-Za-z]{2,24})(?![\w.+-])"""
        ), validator=is_valid_email))
    add(PatternSpec("phone_numbers", "iranian_mobile",
        re_compile(r"""(?<!\d)((?:\+?98|0)9\d{9})(?!\d)""")))
    add(PatternSpec("phone_numbers", "international_phone",
        re_compile(
            r"""(?<![\d+])(\+\d{1,3}[ \t\-]?\d{2,4}[ \t\-]?\d{3,4}[ \t\-]?\d{3,4})(?!\d)"""
        )))

    # ── ip addresses ──
    add(PatternSpec("ips", "ipv4",
        re_compile(
            r"""(?<![\w.])((?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}"""
            r"""(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d))(?!\d|\.\d|\w)"""
        ), validator=is_valid_ip))
    add(PatternSpec("ips", "ipv6",
        re_compile(
            r"""(?<![:\w])((?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}"""
            r"""|(?:[0-9a-fA-F]{1,4}:){1,7}:"""
            r"""|(?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}"""
            r"""|(?:[0-9a-fA-F]{1,4}:){1,5}(?::[0-9a-fA-F]{1,4}){1,2}"""
            r"""|(?:[0-9a-fA-F]{1,4}:){1,4}(?::[0-9a-fA-F]{1,4}){1,3}"""
            r"""|(?:[0-9a-fA-F]{1,4}:){1,3}(?::[0-9a-fA-F]{1,4}){1,4}"""
            r"""|(?:[0-9a-fA-F]{1,4}:){1,2}(?::[0-9a-fA-F]{1,4}){1,5}"""
            r"""|[0-9a-fA-F]{1,4}:(?::[0-9a-fA-F]{1,4}){1,6}"""
            r"""|:(?:(?::[0-9a-fA-F]{1,4}){1,7}|:))(?![:\w])"""
        ), validator=is_valid_ip))

    # ── external urls ──
    add(PatternSpec("urls", "http_url",
        re_compile(r"""\b(https?://[^\s'"<>\)\]\},;]{4,2048})"""),
        validator=is_valid_url))

    # ── files and internal paths ──
    add(PatternSpec("files", "file_reference",
        re_compile(
            r"""['"`]([\w\-./\\]{1,200}\.(?:pem|key|crt|cer|p12|pfx|jks|kdbx|env|sql|bak|"""
            r"""backup|dump|log|csv|xlsx?|docx?|pdf|zip|tar|gz|tgz|7z|rar|json|ya?ml|conf|"""
            r"""cfg|ini|properties|db|sqlite3?|sh|bat|ps1|pcap|htpasswd|npmrc|map))['"`]""",
            re_IGNORECASE)))
    add(PatternSpec("paths_internal", "relative_path",
        re_compile(r"""(?<![\w.:/\\])(\.\.?/[\w\-./%]*[\w\-/%])""")))
    add(PatternSpec("paths_internal", "module_path",
        re_compile(
            r"""(?:\bfrom\s+|\bimport\s+|\brequire\s*\(\s*)"""
            r"""['"]([./][\w\-./%]{1,200})['"]"""
        )))
    add(PatternSpec("paths_internal", "absolute_internal_path",
        re_compile(r"""['"](/[\w\-./%]{2,200})['"]"""),
        validator=is_internal_route))

    # ── system paths ──
    add(PatternSpec("paths_system", "windows_path",
        re_compile(
            r"""(?<![\w])([A-Za-z]:\\(?:[^\\\s'"<>|:*?\n\r]+\\)*[^\\\s'"<>|:*?\n\r]+)"""
        )))
    add(PatternSpec("paths_system", "unix_system_path",
        re_compile(
            r"""(?<![\w.])(/(?:etc|usr|var|home|root|opt|tmp|bin|sbin|lib|"""
            r"""lib64|boot|dev|proc|sys|mnt|media|srv|run|snap|private|"""
            r"""Volumes|Library|System)(?:/[\w\-\.]+)+)"""
        )))

    # ── api endpoints with a known method ──
    add(PatternSpec("api_endpoints_complete", "endpoint_fetch",
        re_compile(
            r"""\bfetch\s*\(\s*[`'"]([^`'"]+)[`'"]"""
            r"""(?:\s*,\s*\{[^}]*?method\s*:\s*[`'"](\w+)[`'"])?"""
        ), capture_groups=(1,), method_group=2, default_method="GET"))
    add(PatternSpec("api_endpoints_complete", "endpoint_axios_method",
        re_compile(
            r"""axios\s*\.\s*(get|post|put|delete|patch|head|options)\s*\(\s*"""
            r"""[`'"]([^`'"]+)[`'"]"""
        ), capture_groups=(2,), method_group=1))
    add(PatternSpec("api_endpoints_complete", "endpoint_axios_object",
        re_compile(
            r"""axios\s*\(\s*\{"""
            r"""(?=[^}]*?url\s*:\s*[`'"]([^`'"]+)[`'"])"""
            r"""(?=[^}]*?method\s*:\s*[`'"](\w+)[`'"])"""
        ), capture_groups=(1,), method_group=2))
    # $.get / $.getJSON / $.post — verb defines the method.
    add(PatternSpec("api_endpoints_complete", "endpoint_jquery_get",
        re_compile(r"""\$\.get\s*\(\s*[`'"]([^`'"]+)[`'"]"""),
        capture_groups=(1,), default_method="GET"))
    add(PatternSpec("api_endpoints_complete", "endpoint_jquery_getjson",
        re_compile(r"""\$\.getJSON\s*\(\s*[`'"]([^`'"]+)[`'"]"""),
        capture_groups=(1,), default_method="GET"))
    add(PatternSpec("api_endpoints_complete", "endpoint_jquery_post",
        re_compile(r"""\$\.post\s*\(\s*[`'"]([^`'"]+)[`'"]"""),
        capture_groups=(1,), default_method="POST"))
    # $.ajax({url, method}) — order-independent, method optional (GET).
    add(PatternSpec("api_endpoints_complete", "endpoint_jquery_ajax_object",
        re_compile(
            r"""\$\.ajax\s*\(\s*\{"""
            r"""(?=[^}]*?url\s*:\s*[`'"]([^`'"]+)[`'"])"""
            r"""(?=[^}]*?method\s*:\s*[`'"](\w+)[`'"])?"""
        ), capture_groups=(1,), method_group=2, default_method="GET"))
    # $.ajax('url', {method}) — settings on second argument.
    add(PatternSpec("api_endpoints_complete", "endpoint_jquery_ajax_url_settings",
        re_compile(
            r"""\$\.ajax\s*\(\s*[`'"]([^`'"]+)[`'"]\s*,\s*\{"""
            r"""(?=[^}]*?method\s*:\s*[`'"](\w+)[`'"])"""
        ), capture_groups=(1,), method_group=2))
    # $.ajax('url') or $.ajax('url', {settings without method}) — GET default.
    add(PatternSpec("api_endpoints_complete", "endpoint_jquery_ajax_url",
        re_compile(
            r"""\$\.ajax\s*\(\s*[`'"]([^`'"]+)[`'"]"""
            r"""(?!\s*,\s*\{[^}]*?method\s*:\s*[`'"])"""
        ), capture_groups=(1,), default_method="GET"))
    add(PatternSpec("api_endpoints_complete", "endpoint_xhr",
        re_compile(
            r"""\.open\s*\(\s*[`'"]([A-Z]+)[`'"]\s*,\s*[`'"]([^`'"]+)[`'"]"""
        ), capture_groups=(2,), method_group=1))
    add(PatternSpec("api_endpoints_complete", "endpoint_express_route",
        re_compile(
            r"""(?:app|router|server)\s*\.\s*(get|post|put|delete|patch|use|all)\s*\(\s*"""
            r"""['"`]([^'"`]+)['"`]"""
        ), capture_groups=(2,), method_group=1))
    add(PatternSpec("api_endpoints_complete", "endpoint_http_method",
        re_compile(
            r"""(?i)\b(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\s+[`'"](/[\w\-/{}$.\?=&:]+)[`'"]"""
        ), capture_groups=(2,), method_group=1))
    add(PatternSpec("api_endpoints_complete", "endpoint_requests_python",
        re_compile(
            r"""requests\s*\.\s*(get|post|put|delete|patch|head|options)\s*\(\s*"""
            r"""['"]([^'"]+)['"]"""
        ), capture_groups=(2,), method_group=1))

    # ── api endpoints without a known method ──
    add(PatternSpec("api_endpoints_partial", "api_path_strong",
        re_compile(
            r"""[`'"](/(?:api|rest)/v\d+(?:/[\w\-{}$.\?=&:]*)?"""
            r"""|/v\d+(?:/[\w\-{}$.\?=&:]*)?|/graphql(?:/[\w\-{}$.\?=&:]*)?)[`'"]"""
        )))
    add(PatternSpec("api_endpoints_partial", "api_path_weak",
        re_compile(
            r"""[`'"](/(?:[\w\-]+/)*(?:api|v\d+|graphql|rest)(?:/[\w\-{}$.\?=&:]*)?)[`'"]"""
        )))

    # ── errors and stack traces ──
    add(PatternSpec("errors", "js_stack_frame",
        re_compile(
            r"""\bat\s+(?:(?:[\w$.<>\[\]]+\s+)?\()?([^\s()]+?\.(?:js|mjs|cjs|jsx|ts|tsx):\d+:\d+)\)?"""
        )))
    add(PatternSpec("errors", "python_traceback",
        re_compile(r"""^(Traceback\s+\(most\s+recent\s+call\s+last\))""",
                   re_MULTILINE)))
    add(PatternSpec("errors", "python_frame",
        re_compile(r"""^\s*File\s+["']([^"']+)["'],\s+line\s+(\d+)""",
                   re_MULTILINE)))
    add(PatternSpec("errors", "java_stack_frame",
        re_compile(r"""\bat\s+([\w$.]+\.(?:[\w$]+)\([\w$]+\.java:\d+\))""")))
    add(PatternSpec("errors", "go_panic",
        re_compile(r"""^panic:\s+(.+)$""", re_MULTILINE)))
    add(PatternSpec("errors", "exception_message",
        re_compile(
            r"""^\s*(?:Uncaught\s+)?(?:Error|TypeError|ReferenceError|"""
            r"""SyntaxError|RangeError|EvalError|URIError|DOMException|"""
            r"""ValueError|KeyError|AttributeError|NameError|ImportError|"""
            r"""ModuleNotFoundError|IOError|OSError|RuntimeError|"""
            r"""ZeroDivisionError|IndexError|StopIteration|"""
            r"""NotImplementedError|AssertionError|PermissionError|"""
            r"""FileNotFoundError|RecursionError|MemoryError|"""
            r"""ConnectionError|TimeoutError|OverflowError|"""
            r"""UnicodeDecodeError|UnicodeEncodeError)\s*:\s*(.+)$""",
            re_MULTILINE)))

    # ── technology names and versions ──
    # Matches package.json style, name@1.2.3, CDN urls, Dockerfile FROM and pip pins.
    for tech in _TECHS:
        esc = re_escape(tech)
        add(PatternSpec(
            category="technology",
            type=f"tech.{_tech_id(tech)}",
            regex=re_compile(
                rf"""(?:["']{esc}["']\s*:\s*["'][~^=<>]*\s*([\d][\d\.\-\w+]*))"""
                rf"""|(?:\b{esc}[@/\-]v?(\d+(?:\.\d+)+))"""
                rf"""|(?:cdn\.jsdelivr\.net/npm/{esc}@(\d+(?:\.\d+)+))"""
                rf"""|(?:cdnjs\.cloudflare\.com/ajax/libs/{esc}/(\d+(?:\.\d+)+))"""
                rf"""|(?:unpkg\.com/{esc}@(\d+(?:\.\d+)+))"""
                rf"""|(?:\bFROM\s+{esc}:(\d+(?:\.\d+)*(?:-[a-z0-9\-]+)?))"""
                rf"""|(?:\b{esc}\s*(?:==|>=|~=|<=)\s*v?(\d+(?:\.\d+)+))""",
                re_IGNORECASE,
            ),
            capture_groups=(1, 2, 3, 4, 5, 6, 7),
        ))
    # Version banners in JavaScript bundles and license comments.
    add(PatternSpec(
        "technology",
        "tech.banner",
        re_compile(
            r"""(?is)/\*{1,2}[!]?"""
            r"""(?:(?!\*/)[\s\S]){0,1200}?"""
            r"""\*?\s*(?:@name\s+(@?[\w][\w@./-]*\s+@version\s+[\d][\w.+-]*)"""
            r"""|(?:@license\s+)?(@?[\w][\w@./-]*\s+v?[\d][\w.+-]*))"""
        ),
        capture_groups=(1, 2),
    ))
    add(PatternSpec("technology", "tech.generator_meta",
        re_compile(
            r"""(?i)name=["']generator["']\s+content=["']([^"']{2,80})["']"""
        )))

    # ── database and service connection data ──
    add(PatternSpec("database", "db_url",
        re_compile(
            r"""(?i)\b(?:mongodb(?:\+srv)?|postgres(?:ql)?|mysql|mariadb|"""
            r"""redis|rediss|amqps?|rabbitmq|sqlserver|oracle|cassandra|"""
            r"""couchdb|neo4j|influxdb|clickhouse|memcached)://[^\s'"<>`,;)]+"""
        ), capture_groups=(0,)))
    add(PatternSpec("database", "jdbc_url",
        re_compile(r"""(?i)\bjdbc:[a-z0-9]+:[^\s'"<>`,;)]+"""),
        capture_groups=(0,)))
    add(PatternSpec("database", "db_env_var",
        re_compile(
            r"""(?i)\b(?:DATABASE_URL|DB_URL|MONGO(?:DB)?_URI|REDIS_URL|"""
            r"""AMQP_URL|RABBITMQ_URL|MYSQL_URL|POSTGRES_URL)\s*[:=]\s*["'`]?([^\s"'`]+)"""
        )))
    add(PatternSpec("database", "redis_connection",
        re_compile(
            r"""(?i)\b(?:redis[_-]?host|redis[_-]?port|redis[_-]?password)"""
            r"""\b\s*[:=]\s*["'`]?([^\s"'`]+)"""
        ), validator=is_valid_value))
    add(PatternSpec("database", "mysql_connection",
        re_compile(
            r"""(?i)\b(?:mysql[_-]?host|mysql[_-]?user|mysql[_-]?password)"""
            r"""\b\s*[:=]\s*["'`]?([^\s"'`]+)"""
        ), validator=is_valid_value))

    # ── infrastructure (Docker, Kubernetes, cloud) ──
    add(PatternSpec("infrastructure", "dockerfile_from",
        re_compile(r"""(?m)^FROM\s+([\w./:\-@]+)(?:\s+AS\s+\w+)?""")))
    add(PatternSpec("infrastructure", "docker_compose_image",
        re_compile(r"""(?m)^\s*image:\s*([\w./:\-@]+)""")))
    add(PatternSpec("infrastructure", "aws_arn",
        re_compile(r"\b(arn:aws[\w\-]*:[\w\-]+:[\w\-]*:\d*:[\w\-/.]+)")))
    add(PatternSpec("infrastructure", "k8s_kind",
        re_compile(
            r"""(?m)^(kind:\s+(?:Pod|Service|Deployment|StatefulSet|"""
            r"""DaemonSet|ConfigMap|Secret|Ingress|Job|CronJob|Namespace|"""
            r"""PersistentVolume|PersistentVolumeClaim|ServiceAccount|"""
            r"""Role|RoleBinding|ClusterRole|ClusterRoleBinding))"""
        )))
    add(PatternSpec("infrastructure", "k8s_api_version",
        re_compile(r"""(?m)^(apiVersion:\s+[\w./]+)""")))

    # ── environment variables, browser storage ──
    add(PatternSpec("env_vars", "sensitive_env_var",
        re_compile(
            r"""(?i)\b(?:process\.env\.|process\.env\[['"]|os\.environ(?:\.get)?\s*\(\s*['"]"""
            r"""|os\.environ\[['"]|ENV\[['"]|getenv\s*\(\s*['"])([A-Z_][A-Z0-9_]{3,})"""
        ), validator=is_sensitive_env_name))
    add(PatternSpec("storage", "local_storage_key",
        re_compile(r"""localStorage\.setItem\s*\(\s*['"`]([^'"`]+)['"`]""")))
    add(PatternSpec("storage", "session_storage_key",
        re_compile(r"""sessionStorage\.setItem\s*\(\s*['"`]([^'"`]+)['"`]""")))
    add(PatternSpec("storage", "cookie_set",
        re_compile(
            r"""(?:document\.cookie\s*=\s*['"`]?|\.cookie\s*\(\s*['"])"""
            r"""\s*([^=;'"`\s]+)\s*="""
        )))
    add(PatternSpec("storage", "local_storage_secret",
        re_compile(
            r"""localStorage\.setItem\s*\(\s*['"`]"""
            r"""[A-Za-z0-9_\-]*(?:token|password|passwd|secret|api[_-]?key"""
            r"""|auth|credential|jwt|session|bearer)[A-Za-z0-9_\-]*"""
            r"""['"`]\s*,\s*['"`]([^'"`]{6,512})['"`]""",
            re_IGNORECASE,
        ), validator=is_valid_secret))
    add(PatternSpec("storage", "session_storage_secret",
        re_compile(
            r"""sessionStorage\.setItem\s*\(\s*['"`]"""
            r"""[A-Za-z0-9_\-]*(?:token|password|passwd|secret|api[_-]?key"""
            r"""|auth|credential|jwt|session|bearer)[A-Za-z0-9_\-]*"""
            r"""['"`]\s*,\s*['"`]([^'"`]{6,512})['"`]""",
            re_IGNORECASE,
        ), validator=is_valid_secret))
    add(PatternSpec("storage", "cookie_secret",
        re_compile(
            r"""(?:document\.cookie\s*=\s*['"`]|\.cookie\s*\(\s*['"])"""
            r"""[A-Za-z0-9_\-]*(?:token|password|passwd|secret|api[_-]?key"""
            r"""|auth|credential|jwt|session|bearer)[A-Za-z0-9_\-]*"""
            r"""\s*=\s*([^;'"`]{3,512})""",
            re_IGNORECASE,
        ), validator=is_valid_secret))

    return specs


# ───────────────────────── helpers ─────────────────────────

def parse_size(raw: str) -> int:
    r = raw.strip().upper()
    if not r:
        raise ArgumentTypeError("empty size value")
    units = {"B": 1, "KB": 1024, "MB": 1024 ** 2, "GB": 1024 ** 3, "TB": 1024 ** 4}
    for unit in ("TB", "GB", "MB", "KB", "B"):
        if r.endswith(unit):
            try:
                value = float(r[: -len(unit)].strip())
            except ValueError:
                raise ArgumentTypeError(f"invalid size: {raw}")
            if value < 0:
                raise ArgumentTypeError(f"negative size: {raw}")
            return int(value * units[unit])
    try:
        return int(r)
    except ValueError:
        raise ArgumentTypeError(f"invalid size: {raw}")


def fmt_size(n: float) -> str:
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024 or unit == "TB":
            return f"{int(n)} B" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024.0
    return f"{n:.1f} TB"


def make_preview(content: str, start: int, end: int, context: int = 30) -> str:
    s = max(0, start - context)
    e = min(len(content), end + context)
    piece = " ".join(content[s:e].split())
    return piece if len(piece) <= 200 else piece[:197] + "..."


def parse_comma_list(raw: str | None) -> list[str]:
    if not raw:
        return []
    return [item.strip() for item in raw.split(",") if item.strip()]


def file_ext(path: Path) -> str:
    name = path.name.lower()
    # Handle multi-part extensions like .env.local, .env.production, .gitignore
    if name.startswith(".env."):
        return ".env"
    if name.startswith("."):
        # For dotfiles, return the full suffix including all parts after first dot
        # e.g., ".env.local" -> ".env.local", ".gitignore" -> ".gitignore"
        return name
    return path.suffix.lower()


def detect_kind(path: Path) -> str:
    ext = file_ext(path)
    if ext in PDF_EXTENSIONS:
        return "pdf"
    if ext in OFFICE_EXTENSIONS:
        return "office"
    if ext in IMAGE_EXTENSIONS:
        return "image"
    if ext in ARCHIVE_EXTENSIONS:
        return "archive"
    if ext in TEXT_EXTENSIONS:
        return "text"
    try:
        with path.open("rb") as fh:
            head = fh.read(4096)
    except OSError:
        return "unknown"
    if not head:
        return "text"
    if head.startswith(b"%PDF-"):
        return "pdf"
    if head.startswith(IMAGE_MAGIC):
        return "image"
    if _is_bmp(head):
        return "image"
    if head[:4] == _WEBP_RIFF and head[8:12] == _WEBP_BRAND:
        return "image"
    if head[4:8] == _HEIF_BOX and head[8:12] in _HEIF_BRANDS:
        return "image"
    if head.startswith((b"\xef\xbb\xbf", b"\xff\xfe", b"\xfe\xff")):
        return "text"
    if b"\x00" in head:
        return "binary"
    return "text"


def read_text(path: Path) -> str:
    raw = path.read_bytes()
    if raw.startswith(b"\xef\xbb\xbf"):
        return raw[3:].decode("utf-8", errors="replace")
    if raw.startswith(b"\xff\xfe"):
        return raw[2:].decode("utf-16-le", errors="replace")
    if raw.startswith(b"\xfe\xff"):
        return raw[2:].decode("utf-16-be", errors="replace")
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        try:
            return raw.decode("cp1252")
        except UnicodeDecodeError:
            return raw.decode("latin-1", errors="replace")


def extract_printable_strings(data: bytes) -> str:
    return "\n".join(m.decode("utf-8", errors="ignore") for m in PRINTABLE_RE.findall(data))


def is_sensitive_meta_key(key: str) -> bool:
    low = key.lower()
    if low in SENSITIVE_META_KEYS:
        return True
    return low.startswith("gps.") and "version" not in low


def extract_pdf(path: Path) -> tuple[str, dict[str, str]]:
    if not _HAS_PYPDF:
        return "", {}
    reader = _PdfReader(str(path))
    if reader.is_encrypted:
        try:
            opened = reader.decrypt("")
        except Exception:
            opened = 0
        if not opened:
            raise ValueError("encrypted PDF")
    parts: list[str] = []
    for page in reader.pages:
        try:
            parts.append(page.extract_text() or "")
        except Exception:
            pass
        # Link annotations carry URLs that are absent from the page text.
        try:
            for ref in page.get("/Annots") or []:
                action = ref.get_object().get("/A")
                if action is not None:
                    uri = action.get_object().get("/URI")
                    if uri:
                        parts.append(str(uri))
        except Exception:
            pass
    try:
        for name, fld in (reader.get_fields() or {}).items():
            value = getattr(fld, "value", None)
            if value:
                parts.append(f"{name}: {value}")
    except Exception:
        pass
    meta: dict[str, str] = {}
    try:
        for k, v in (reader.metadata or {}).items():
            if v:
                meta[str(k).lstrip("/")] = str(v)[:4096]
    except Exception:
        pass
    return "\n".join(parts), meta


_META_SKIP = frozenset({
    "MakerNote", "PrintImageMatching", "ExifOffset", "GPSInfo",
    "InteroperabilityOffset", "ComponentsConfiguration", "ExifVersion",
    "FlashPixVersion",
})
_INFO_SKIP = frozenset({
    "exif", "icc_profile", "transparency", "dpi", "gamma", "progressive",
    "progression", "jfif", "jfif_version", "jfif_unit", "jfif_density",
    "adobe", "adobe_transform", "duration", "loop", "background", "version",
})


def _fmt_number(value: Any) -> str | None:
    """Render int/float/IFDRational as decimal; None for str/bool/others."""
    if isinstance(value, (bool, str)):
        return None
    try:
        return f"{float(value):g}"
    except (TypeError, ValueError):
        return None


def _meta_text(value: Any, *, key: str = "") -> str:
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="ignore").replace("\x00", "").strip()[:4096]

    # GPS coordinates: (deg, min, sec) rationals -> DMS string.
    if (key.endswith(("Latitude", "Longitude"))
            and isinstance(value, (tuple, list)) and len(value) == 3):
        try:
            deg, minutes, seconds = (float(x) for x in value)
            return f"{deg:.0f}°{minutes:.0f}'{seconds:.2f}\""
        except (TypeError, ValueError):
            pass

    if isinstance(value, (tuple, list)):
        parts = []
        for item in value:
            if isinstance(item, bytes):
                parts.append(item.decode("utf-8", errors="ignore"))
                continue
            num = _fmt_number(item)
            parts.append(num if num is not None else str(item))
        return ", ".join(parts).replace("\x00", "").strip()[:4096]

    num = _fmt_number(value)
    if num is not None:
        return num
    return str(value).replace("\x00", "").strip()[:4096]


def extract_image_exif(path: Path) -> dict[str, str]:
    """Return EXIF, GPS and embedded text-chunk metadata. Pixels are never read."""
    if not _HAS_PIL:
        return {}
    result: dict[str, str] = {}
    with _PILImage.open(path) as img:
        exif = img.getexif()
        for tag_id, value in exif.items():
            name = _PILExifTags.TAGS.get(tag_id, str(tag_id))
            if name not in _META_SKIP:
                result[name] = _meta_text(value, key=name)
        for ifd_id, table, prefix in (
            (_EXIF_IFD, _PILExifTags.TAGS, ""),
            (_GPS_INFO_IFD, _PILExifTags.GPSTAGS, "GPS."),
        ):
            try:
                ifd = exif.get_ifd(ifd_id)
            except Exception:
                continue
            for tag_id, value in ifd.items():
                name = table.get(tag_id, str(tag_id))
                if name not in _META_SKIP:
                    full_key = prefix + name
                    result[full_key] = _meta_text(value, key=full_key)
        for key, value in img.info.items():
            if key in _INFO_SKIP or not isinstance(value, (str, bytes)):
                continue
            result[str(key)] = _meta_text(value, key=str(key))
    return result


OFFICE_META_RE = re_compile(
    r"<(?:[\w\-]+:)?([\w\-]+)(?:\s[^>]*)?>([^<]{1,512})</(?:[\w\-]+:)?\1>"
)
OFFICE_TAG_RE = re_compile(r"<[^>]+>")
OFFICE_META_FILES = frozenset({
    "docprops/core.xml", "docprops/app.xml", "docprops/custom.xml", "meta.xml",
})


def extract_office(path: Path) -> tuple[str, dict[str, str]]:
    """Read text and document properties from OOXML/ODF packages (zip of xml)."""
    parts: list[str] = []
    meta: dict[str, str] = {}
    total = 0
    with ZipFile(path) as zf:
        for info in zf.infolist():
            name = info.filename.lower()
            if info.is_dir() or info.file_size > MAX_OFFICE_ENTRY:
                continue
            if not name.endswith((".xml", ".rels")):
                continue
            total += info.file_size
            if total > MAX_OFFICE_TOTAL:
                break
            xml = zf.read(info).decode("utf-8", errors="replace")
            if name in OFFICE_META_FILES:
                for m in OFFICE_META_RE.finditer(xml):
                    meta[m.group(1)] = m.group(2).strip()
            elif name.endswith(".rels"):
                parts.append(xml)
            else:
                parts.append(OFFICE_TAG_RE.sub(" ", xml))
    return "\n".join(parts), meta


# ───────────────────────── scanning ─────────────────────────

def extract_match_value(match: re_Match[str], spec: PatternSpec) -> str | None:
    value: str | None = None
    for g in spec.capture_groups:
        try:
            v = match.group(g)
        except (IndexError, ValueError):
            continue
        if v:
            value = v.strip()
            break
    if value is None:
        value = match.group(0).strip()
    if spec.type == "http_url":
        value = value.rstrip(".,:")
    if value and (spec.method_group or spec.default_method):
        method: str | None = None
        if spec.method_group:
            try:
                method = match.group(spec.method_group)
            except (IndexError, ValueError):
                method = None
        method = method or spec.default_method
        if method:
            value = f"{method.upper()} {value}"
    return value or None


def build_line_index(text: str) -> list[int]:
    starts = [0]
    pos = text.find("\n")
    while pos != -1:
        starts.append(pos + 1)
        pos = text.find("\n", pos + 1)
    return starts


def line_col(starts: list[int], pos: int) -> tuple[int, int]:
    # Binary search keeps line lookup O(log n) on very large bundles.
    idx = bisect_right(starts, pos) - 1
    return idx + 1, pos - starts[idx] + 1


def scan_content(
    content: str,
    file_path: str,
    patterns: list[PatternSpec],
    excluded_patterns: tuple[re_Pattern[str], ...],
    source: str = "content",
    fixed_line: int = 0,
) -> list[Finding]:
    findings: list[Finding] = []
    starts = None if fixed_line else build_line_index(content)
    for spec in patterns:
        for match in spec.regex.finditer(content):
            value = extract_match_value(match, spec)
            if not value:
                continue
            if spec.validator and not spec.validator(value):
                continue
            if any(pat.search(value) for pat in excluded_patterns):
                continue
            if starts is None:
                line_no, col = fixed_line, 0
            else:
                line_no, col = line_col(starts, match.start())
                if spec.type in _COMMENT_FILTER_TYPES:
                    line_prefix = content[starts[line_no - 1]:match.start()]
                    if _COMMENT_PREFIX_RE.match(line_prefix):
                        continue
            findings.append(Finding(
                category=spec.category,
                type=spec.type,
                value=value,
                file=file_path,
                line=line_no,
                column=col,
                preview=make_preview(content, match.start(), match.end()),
                source=source,
            ))
    return findings


def scan_file(
    path: Path,
    patterns: list[PatternSpec],
    excluded_categories: frozenset[str],
    excluded_patterns: tuple[re_Pattern[str], ...],
) -> FileResult:
    start = time_perf_counter()

    def elapsed() -> float:
        return (time_perf_counter() - start) * 1000

    try:
        size = path.stat().st_size
    except OSError as exc:
        return FileResult(str(path), 0, "unknown", [], [f"stat: {exc}"],
                          elapsed(), len(patterns), "stat_error")
    try:
        kind = detect_kind(path)
    except Exception as exc:
        return FileResult(str(path), size, "unknown", [], [f"detect: {exc}"],
                          elapsed(), len(patterns), "detect_error")
    if kind == "archive":
        return FileResult(str(path), size, kind, [], [], elapsed(), 0,
                          "archive_skipped")

    errors: list[str] = []
    findings: list[Finding] = []
    content = ""
    metadata: dict[str, str] = {}
    try:
        if kind == "text":
            content = read_text(path)
        elif kind == "pdf":
            content, metadata = extract_pdf(path)
        elif kind == "image":
            metadata = extract_image_exif(path)
        elif kind == "office":
            content, metadata = extract_office(path)
        elif kind == "binary":
            content = extract_printable_strings(path.read_bytes())
    except Exception as exc:
        errors.append(f"{kind}: {exc}")

    if content:
        findings.extend(scan_content(content, str(path), patterns, excluded_patterns))

    for key, val in metadata.items():
        # Metadata values go through the normal patterns (emails, paths, ...).
        findings.extend(scan_content(
            f"{key}: {val}", str(path), patterns, excluded_patterns,
            source=f"metadata.{kind}", fixed_line=-1))
        # Identifying tags (author, GPS, camera serial, ...) are reported directly.
        if ("metadata" not in excluded_categories and val.strip()
                and is_sensitive_meta_key(key)):
            findings.append(Finding(
                category="metadata",
                type=f"{kind}_tag",
                value=f"{key}: {val.strip()[:512]}",
                file=str(path),
                line=-1,
                column=0,
                source=f"metadata.{kind}",
            ))

    return FileResult(
        path=str(path),
        size=size,
        kind=kind,
        findings=findings,
        errors=errors,
        duration_ms=elapsed(),
        patterns_checked=len(patterns),
    )


def matches_ext(path: Path, explicit_exts: tuple[str, ...], scan_all: bool) -> bool:
    if scan_all:
        return True
    ext = file_ext(path)
    if explicit_exts:
        return ext in explicit_exts
    return ext == ".js"


def collect_files(
    root: Path,
    explicit_exts: tuple[str, ...],
    scan_all: bool,
    recursive: bool,
    use_default_excludes: bool,
) -> list[Path]:
    if root.is_file():
        return [root]
    if not root.is_dir():
        return []
    result: list[Path] = []
    if recursive:
        for dirpath, dirnames, filenames in os_walk(str(root), followlinks=False):
            if use_default_excludes:
                dirnames[:] = [d for d in dirnames if d not in DEFAULT_EXCLUDES]
            for name in filenames:
                p = Path(dirpath) / name
                if matches_ext(p, explicit_exts, scan_all):
                    result.append(p)
    else:
        try:
            for entry in root.iterdir():
                try:
                    if entry.is_file() and matches_ext(entry, explicit_exts, scan_all):
                        result.append(entry)
                except OSError:
                    continue
        except OSError:
            pass
    return result


class DuplicateTracker:
    """Detects identical files. Size is compared first; SHA-256 is computed
    lazily, and only for files that share a size with an earlier file."""

    def __init__(self, enabled: bool) -> None:
        self.enabled = enabled
        self._by_size: dict[int, list[Path]] = {}
        self._digests: dict[Path, str] = {}

    def _digest(self, path: Path) -> str:
        cached = self._digests.get(path)
        if cached is None:
            h = sha256()
            with path.open("rb") as fh:
                for chunk in iter(lambda: fh.read(1 << 20), b""):
                    h.update(chunk)
            cached = h.hexdigest()
            self._digests[path] = cached
        return cached

    def check(self, path: Path, size: int) -> Path | None:
        if not self.enabled:
            return None
        peers = self._by_size.setdefault(size, [])
        try:
            if peers:
                digest = self._digest(path)
                for other in peers:
                    if self._digest(other) == digest:
                        return other
        except OSError:
            pass
        peers.append(path)
        return None


# ───────────────────────── reporting ─────────────────────────

def aggregate_findings(findings: list[Finding]) -> list[dict[str, Any]]:
    """Merge findings into unique values; one value is reported only once."""
    order = {name: i for i, name in enumerate(CATEGORY_ORDER)}
    grouped: dict[tuple[str, str], dict[str, Any]] = {}
    for f in findings:
        key = (f.value, f.type if f.category == "technology" else "")
        bucket = grouped.get(key)
        if bucket is None:
            bucket = {"value": f.value, "types": {}, "sources": set(),
                      "occurrences": [], "locs": set()}
            grouped[key] = bucket
        bucket["types"].setdefault(f.category, set()).add(f.type)
        bucket["sources"].add(f.source)
        loc = (f.file, f.line)
        if loc not in bucket["locs"]:
            bucket["locs"].add(loc)
            bucket["occurrences"].append({
                "file": f.file, "line": f.line, "column": f.column,
                "preview": f.preview, "source": f.source,
            })

    out: list[dict[str, Any]] = []
    for bucket in grouped.values():
        category = min(bucket["types"], key=lambda c: order.get(c, 999))
        out.append({
            "category": category,
            "type": ", ".join(sorted(bucket["types"][category])),
            "value": bucket["value"],
            "sources": sorted(bucket["sources"]),
            "occurrences": bucket["occurrences"],
        })

    # A path that already appears with an HTTP method is not repeated as a
    # method-less endpoint or as a plain internal path.
    complete_paths = {
        item["value"].split(" ", 1)[-1]
        for item in out if item["category"] == "api_endpoints_complete"
    }
    out = [
        item for item in out
        if not (item["category"] in ("api_endpoints_partial", "paths_internal")
                and item["value"] in complete_paths)
    ]
    out.sort(key=lambda x: (order.get(x["category"], 999), x["type"], x["value"]))
    return out


def format_location(occ: dict[str, Any]) -> str:
    if occ["line"] > 0:
        return f"{occ['file']}:{occ['line']}:{occ['column']}"
    return f"{occ['file']} ({occ['source']})"


def ordered_categories(by_cat: dict[str, Any]) -> list[str]:
    known = [c for c in CATEGORY_ORDER if c in by_cat]
    return known + [c for c in by_cat if c not in CATEGORY_ORDER]





def render_text(report: ScanReport, verbose_level: int) -> str:
    aggregated = aggregate_findings(report.findings)
    lines: list[str] = []
    ap = lines.append

    total_matches = sum(
        len(item["occurrences"]) for item in aggregated
    )

    ap("=" * 72)
    ap("  SenseScan | Sensitive Data Report")
    ap("=" * 72)
    ap(f"  Files scanned      : {report.scanned_files}")
    ap(f"  Unique findings    : {len(aggregated)}")
    ap(f"  Total matches      : {total_matches}")

    if verbose_level >= 3:
        ap(f"  Files skipped      : {report.skipped_files}")
        ap(f"  Scan duration      : {report.duration_sec:.2f}s")

    ap("=" * 72)
    ap("")

    if not aggregated:
        ap("  No sensitive data found.")
        ap("=" * 72)
        return "\n".join(lines)

    # Credentials combines usernames and password findings.
    credentials = {
        "Usernames": [],
        "Passwords": [],
    }

    other_categories: dict[str, list[str]] = {}
    technologies: list[str] = []

    tech_names = {
        _tech_id(name): name
        for name in _TECHS
    }

    for item in aggregated:
        category = item["category"]
        value = item["value"]

        if category == "usernames":
            credentials["Usernames"].append(value)

        elif category == "credentials":
            credentials["Passwords"].append(value)

        elif category == "technology":
            tech_type = item["type"]

            if tech_type.startswith("tech.") and tech_type != "tech.banner" and tech_type != "tech.generator_meta":
                tech_name = tech_names.get(
                    tech_type.removeprefix("tech."),
                    tech_type.removeprefix("tech.")
                )
                technologies.append(f"{tech_name}: {value}")
            else:
                technologies.append(value)

        else:
            other_categories.setdefault(category, []).append(value)

    # Render credentials first.
    if any(credentials.values()):
        ap("Credentials")

        for label in ("Usernames", "Passwords"):
            values = credentials[label]

            if not values:
                continue

            ap(f"  {label}:")

            for value in values:
                ap(f"    - {value}")

            ap("")

    # Render technologies in one section.
    if technologies:
        ap("Technologies")

        for technology in sorted(set(technologies), key=str.lower):
            ap(f"  - {technology}")

        ap("")

    # Render all remaining categories.
    for category in CATEGORY_ORDER:
        if category not in other_categories:
            continue

        values = other_categories[category]

        title = category.replace("_", " ").title()
        ap(title)

        for value in values:
            ap(f"  - {value}")

        ap("")

    if verbose_level >= 4 and report.errors:
        ap("Errors")
        for error in report.errors:
            ap(f"  - {error}")
        ap("")

    ap("=" * 72)

    return "\n".join(lines)





def render_json(report: ScanReport) -> str:
    aggregated = aggregate_findings(report.findings)
    by_cat: dict[str, int] = {}
    by_type: dict[str, int] = {}
    safe_findings = [
            {
                "category": item["category"],
                "type": item["type"],
                "value": item["value"],
                "sources": item["sources"],
                "occurrence_count": len(item["occurrences"]),
            }
            for item in aggregated
        ]
    
    for item in aggregated:
        by_cat[item["category"]] = by_cat.get(item["category"], 0) + 1
        by_type[item["type"]] = by_type.get(item["type"], 0) + 1

    payload = {
        "meta": {
            "tool": "sensitive_scanner",
            "version": TOOL_VERSION,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "started_at": report.started_at,
            "duration_sec": round(report.duration_sec, 3),
            "base_path": report.base_path,
            "platform": sys_platform,
            "files_scanned": report.scanned_files,
            "files_skipped": report.skipped_files,
            "unique_findings": len(aggregated),
            "total_matches": sum(len(i["occurrences"]) for i in aggregated),
        },
        "options": report.options,
        "summary": {"by_category": by_cat, "by_type": by_type},
        "findings": safe_findings,
        "skipped": {
            "large_files": [{"path": p, "size": s} for p, s in report.skipped_large],
            "duplicate_files": [{"path": p, "original": o}
                                for p, o in report.duplicate_files],
        },
        "errors": report.errors,
    }
    return json_dumps(payload, ensure_ascii=False, indent=2)


HTML_STYLE = """:root{--bg:#f6f7fb;--card:#fff;--text:#1d2333;--muted:#667085;--line:#e4e7ec;--accent:#4f46e5;--high:#d92d20;--info:#175cd3}
@media(prefers-color-scheme:dark){:root{--bg:#0f1220;--card:#181c2f;--text:#e8eaf3;--muted:#9aa3b8;--line:#2a3050;--accent:#8b8bff;--high:#ff6b5e;--info:#6aa6ff}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--text);font:14px/1.5 system-ui,Segoe UI,Roboto,sans-serif}
.wrap{max-width:1100px;margin:0 auto;padding:32px 20px}
h1{margin:0 0 4px;font-size:24px}.sub{color:var(--muted);margin-bottom:24px;word-break:break-all}
.stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:12px;margin-bottom:24px}
.stat{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:14px 16px}
.stat b{display:block;font-size:24px}.stat span{color:var(--muted);font-size:12px;text-transform:uppercase;letter-spacing:.04em}
input{width:100%;padding:10px 14px;border-radius:10px;border:1px solid var(--line);background:var(--card);color:var(--text);margin-bottom:16px}
details.cat{background:var(--card);border:1px solid var(--line);border-radius:12px;margin-bottom:12px;overflow:hidden}
summary{cursor:pointer;padding:12px 16px;font-weight:600;display:flex;justify-content:space-between;align-items:center}
.count{background:var(--accent);color:#fff;border-radius:999px;padding:0 10px;font-size:12px}
table{width:100%;border-collapse:collapse}td{padding:10px 16px;border-top:1px solid var(--line);vertical-align:top}
code{font:12.5px ui-monospace,Menlo,Consolas,monospace;word-break:break-all}
.tag{display:inline-block;border-radius:6px;padding:1px 8px;font-size:11px;border:1px solid currentColor}
.tag.high{color:var(--high)}.tag.info{color:var(--info)}
.loc{color:var(--muted);font-size:12px;word-break:break-all}
"""

HTML_SCRIPT = (
    "<script>document.getElementById('q').addEventListener('input',function(e){"
    "var t=e.target.value.toLowerCase();"
    "document.querySelectorAll('tr.row').forEach(function(r){"
    "r.style.display=r.textContent.toLowerCase().indexOf(t)>-1?'':'none'})});</script>"
)


def render_html(report: ScanReport) -> str:
    aggregated = aggregate_findings(report.findings)
    by_cat: dict[str, list[dict[str, Any]]] = {}
    for item in aggregated:
        by_cat.setdefault(item["category"], []).append(item)
    total = sum(len(i["occurrences"]) for i in aggregated)
    esc = html_escape
    out = [
        '<!doctype html><html lang="en"><head><meta charset="utf-8">',
        '<meta name="viewport" content="width=device-width,initial-scale=1">',
        "<title>Sensitive Data Scan Report</title>",
        f'<style>{HTML_STYLE}</style></head><body><div class="wrap">',
        "<h1>Sensitive Data Scan Report</h1>",
        f'<div class="sub">{esc(report.base_path)} &middot; {esc(report.started_at)}</div>',
        '<div class="stats">',
    ]
    for label, number in (
        ("Files scanned", report.scanned_files),
        ("Files skipped", report.skipped_files),
        ("Unique findings", len(aggregated)),
        ("Total matches", total),
        ("Duration", f"{report.duration_sec:.2f}s"),
    ):
        out.append(f'<div class="stat"><b>{number}</b><span>{label}</span></div>')
    out.append("</div>")
    if not aggregated:
        out.append("<p>No sensitive data found.</p>")
    else:
        out.append('<input id="q" placeholder="Filter findings..." autocomplete="off">')
        for cat in ordered_categories(by_cat):
            items = by_cat[cat]
            sev = "high" if cat in HIGH_SEVERITY else "info"
            title = esc(cat.replace("_", " ").title())
            out.append(
                f'<details class="cat" open><summary>{title}'
                f'<span class="count">{len(items)}</span></summary><table>')
            for item in items:
                match_count = len(item["occurrences"])
                out.append(
                    f'<tr class="row">'
                    f'<td><span class="tag {sev}">{esc(item["type"])}</span></td>'
                    f'<td><code>{esc(item["value"])}</code></td>'
                    f'<td>{match_count} matches</td>'
                    f'</tr>')
            out.append("</table></details>")
        out.append(HTML_SCRIPT)
    out.append("</div></body></html>")
    return "\n".join(out)


def render_report(report: ScanReport, fmt: str, verbose_level: int) -> str:
    if fmt == "json":
        return render_json(report)
    if fmt == "html":
        return render_html(report)
    return render_text(report, verbose_level)


def resolve_format(args: Namespace) -> str:
    if args.format:
        return args.format
    if args.output:
        suffix = Path(args.output).suffix.lower()
        if suffix == ".json":
            return "json"
        if suffix in (".html", ".htm"):
            return "html"
    return "text"


# ───────────────────────── cli ─────────────────────────

def parse_args(argv: list[str]) -> Namespace:
    parser = ArgumentParser(
        prog="sensitive_scanner",
        description="Scan for sensitive data (default: *.js in the current directory only).",
        epilog=(
            "Exit codes: 0=success, 1=findings (with --fail-on-findings), "
            "2=error, 3=no files matched, 130=interrupted"
        ),
    )
    parser.add_argument("-p", "--path", default=None,
                        help="File or directory to scan (default: current directory).")
    parser.add_argument("-r", "--recursive", action="store_true",
                        help="Recurse into subdirectories.")
    parser.add_argument("-a", "--all", dest="scan_all", action="store_true",
                        help="Scan all file types.")
    parser.add_argument("--ext", default=None,
                        help="Comma-separated extensions, e.g. js,ts,py,json.")
    parser.add_argument("--max-size", type=parse_size, default=DEFAULT_MAX_SIZE,
                        help=f"Max file size (default: {fmt_size(DEFAULT_MAX_SIZE)}).")
    parser.add_argument("--exclude", default=None,
                        help="Comma-separated categories to exclude.")
    parser.add_argument("--exclude-pattern", default=None,
                        help="Comma-separated regex patterns to exclude values.")
    parser.add_argument("--no-dedupe", action="store_false", dest="dedupe",
                        help="Scan files even if their content is identical to an earlier file.")
    parser.add_argument("--no-default-excludes", action="store_true",
                        help="Do not skip node_modules, .git, etc. when recursing.")
    parser.add_argument("-v", action="count", default=0,
                        help="Increase verbosity (-v, -vv, -vvv, -vvvv).")
    parser.add_argument("--verbose", type=int, default=None,
                        help="Verbosity level 0-4.")
    parser.add_argument("--output", default=None,
                        help="Write report to file.")
    parser.add_argument("--format", choices=("text", "json", "html"), default=None,
                        help="Report format (default: inferred from --output extension, else text).")
    parser.add_argument("--fail-on-findings", action="store_true",
                        help="Exit 1 if any findings (for CI).")
    parser.add_argument("--no-color", action="store_true",
                        help="Disable ANSI colors.")
    parser.add_argument("--version", action="version",
                        version=f"%(prog)s {TOOL_VERSION}")

    args = parser.parse_args(argv)

    if args.verbose is not None:
        if not 0 <= args.verbose <= 4:
            parser.error("--verbose must be 0..4")
        args.verbosity = args.verbose
    else:
        args.verbosity = min(args.v, 4)
    return args


def check_optional_lib(kind: str) -> str | None:
    if kind == "pdf" and not _HAS_PYPDF:
        return ("pypdf is not installed; PDF text/metadata extraction disabled. "
                "Install with: pip install pypdf")
    if kind == "image" and not _HAS_PIL:
        return ("Pillow is not installed; image metadata extraction disabled. "
                "Install with: pip install pillow")
    return None


def main(argv: list[str] | None = None) -> int:
    for stream in (sys_stdout, sys_stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass

    try:
        args = parse_args(argv if argv is not None else sys_argv[1:])
    except SystemExit as exc:
        if isinstance(exc.code, int):
            return exc.code
        return EXIT_SUCCESS if exc.code is None else EXIT_ERROR

    init_colors(args.no_color)
    verbose = args.verbosity
    out_format = resolve_format(args)
    # With json/html on stdout, live progress goes to stderr to keep stdout clean.
    live = sys_stderr if (out_format != "text" and not args.output) else sys_stdout

    def say(message: str) -> None:
        print(message, file=live)

    base = Path(args.path).resolve() if args.path else Path(os_getcwd()).resolve()
    if not base.exists():
        print(Colors.red(f"Error: path does not exist: {base}"), file=sys_stderr)
        return EXIT_ERROR
    if base.is_file() and base.suffix.lower() in ARCHIVE_EXTENSIONS:
        print(Colors.red(f"Error: archive input is not supported: {base.name}"),
              file=sys_stderr)
        return EXIT_ERROR

    explicit_exts: tuple[str, ...] = tuple(
        "." + e.strip().lstrip(".").lower()
        for e in (args.ext or "").split(",") if e.strip()
    )
    scan_all = args.scan_all

    excluded_categories = frozenset(c.lower() for c in parse_comma_list(args.exclude))
    unknown = excluded_categories - ALL_CATEGORIES
    if unknown:
        print(Colors.yellow(
            f"Warning: unknown categories ignored: {', '.join(sorted(unknown))}"),
            file=sys_stderr)

    excluded_pattern_strs = parse_comma_list(args.exclude_pattern)
    compiled_excludes: list[re_Pattern[str]] = []
    for pat in excluded_pattern_strs:
        try:
            compiled_excludes.append(re_compile(pat))
        except Exception as exc:
            print(Colors.red(
                f"Error: invalid --exclude-pattern '{pat}': {exc}"), file=sys_stderr)
            return EXIT_ERROR
    exclude_patterns_tuple = tuple(compiled_excludes)

    try:
        patterns = build_patterns()
    except Exception as exc:
        print(Colors.red(f"Error: failed to build patterns: {exc}"), file=sys_stderr)
        return EXIT_ERROR
    active = [p for p in patterns if p.category not in excluded_categories]

    report = ScanReport(
        base_path=str(base),
        started_at=datetime.now(timezone.utc).isoformat(),
        excluded_categories=sorted(excluded_categories),
        excluded_patterns=excluded_pattern_strs,
        options={
            "recursive": args.recursive,
            "scan_all": scan_all,
            "extensions": list(explicit_exts) if explicit_exts else [".js"],
            "max_size": args.max_size,
            "dedupe": args.dedupe,
            "use_default_excludes": not args.no_default_excludes,
            "verbosity": verbose,
            "format": out_format,
        },
    )

    start = time_perf_counter()
    exit_code = EXIT_SUCCESS
    tracker = DuplicateTracker(args.dedupe)
    warned: set[str] = set()
    # Live progress is only meaningful on a terminal; when the output
    # stream is redirected or piped we skip it to avoid writing one
    # line per scanned file into logs.
    show_progress = verbose == 0 and getattr(live, "isatty", lambda: False)()

    try:
        files = collect_files(
            base,
            explicit_exts=explicit_exts,
            scan_all=scan_all,
            recursive=args.recursive,
            use_default_excludes=not args.no_default_excludes,
        )
        files.sort()

        if not files:
            ext_desc = ", ".join(explicit_exts) if explicit_exts else (
                "all" if scan_all else ".js")
            print(Colors.yellow(
                f"No files matched (filter: {ext_desc}). "
                f"Use --ext or --all to include other file types."),
                file=sys_stderr)
            report.duration_sec = time_perf_counter() - start
            print(render_report(report, out_format, verbose))
            return EXIT_NO_FILES

        say(Colors.cyan(
            f"\n  SenseScan | Starting scan of {len(files)} files\n"
        ))

        for file_index, file_path in enumerate(files, start=1):
            if show_progress:
                line = (
                    f"  Progress: {file_index - 1}/{len(files)}"
                    f" | Scanned: {report.scanned_files}"
                    f" | Skipped: {report.skipped_files}"
                )
                print(f"\r{line.ljust(80)}", end="", flush=True, file=live)

            try:
                size = file_path.stat().st_size
            except OSError as exc:
                report.errors.append(f"{file_path}: {exc}")
                continue

            if size > args.max_size:
                report.skipped_large.append((str(file_path), size))
                report.skipped_files += 1
                if verbose >= 3:
                    say(Colors.yellow(
                        f"  [skip] {file_path.name} ({fmt_size(size)}) > "
                        f"--max-size {fmt_size(args.max_size)}"))
                continue

            original = tracker.check(file_path, size)
            if original is not None:
                report.duplicate_files.append((str(file_path), str(original)))
                report.skipped_files += 1
                if verbose >= 3:
                    say(Colors.dim(f"  [dupe] {file_path.name} == {original}"))
                continue

            if verbose >= 1:
                say(Colors.blue(f"  Scanning: {file_path}"))

            try:
                result = scan_file(file_path, active, excluded_categories,
                                   exclude_patterns_tuple)
            except Exception as exc:
                report.errors.append(f"{file_path}: unhandled {exc}")
                if verbose >= 4:
                    say(Colors.red(f"  error: {traceback_format_exc()}"))
                continue

            report.errors.extend(f"{file_path}: {err}" for err in result.errors)

            if result.skipped_reason:
                report.skipped_files += 1
                if verbose >= 3:
                    say(Colors.dim(f"  [skip] {file_path.name} ({result.skipped_reason})"))
                continue

            if result.kind in ("pdf", "image") and result.kind not in warned:
                warned.add(result.kind)
                warn = check_optional_lib(result.kind)
                if warn:
                    print(Colors.yellow(f"  warning: {warn}"), file=sys_stderr)

            report.scanned_files += 1
            report.file_results.append(result)
            report.findings.extend(result.findings)

            if verbose >= 1:
                say(f"      -> {len(result.findings)} finding(s)")
                for f in result.findings:
                    say(f"         [{f.category}/{f.type}] {f.value}")

            if verbose >= 2:
                found_cats = {f.category for f in result.findings}
                searched_cats = {spec.category for spec in active}
                for cat in sorted(searched_cats - found_cats):
                    say(Colors.dim(f"         (no findings in: {cat})"))

            if verbose >= 3:
                say(Colors.dim(
                    f"         time={result.duration_ms:.1f}ms "
                    f"size={fmt_size(result.size)} "
                    f"patterns={result.patterns_checked} kind={result.kind}"))

            if verbose >= 4:
                for err in result.errors:
                    say(Colors.red(f"         ! {err}"))

    except KeyboardInterrupt:
        print(Colors.yellow("\nInterrupted by user."), file=sys_stderr)
        exit_code = EXIT_INTERRUPTED
    except Exception as exc:
        print(Colors.red(f"Fatal: {exc}"), file=sys_stderr)
        if verbose >= 4:
            print(traceback_format_exc(), file=sys_stderr)
        exit_code = EXIT_ERROR

    if show_progress:
        label = "Scan completed" if exit_code == EXIT_SUCCESS else "Scan stopped"
        line = (
            f"  {label} | Scanned: {report.scanned_files}"
            f" | Skipped: {report.skipped_files}"
        )
        print(f"\r{line.ljust(80)}", file=live)

    report.duration_sec = time_perf_counter() - start
    rendered = render_report(report, out_format, verbose)

    if args.output:
        out_path = Path(args.output)
        try:
            out_path.write_text(rendered + "\n", encoding="utf-8")
        except OSError as exc:
            print(Colors.red(f"Error writing output: {exc}"), file=sys_stderr)
            return EXIT_ERROR
        print(Colors.green(f"Report saved to {out_path}"))
        print(f"  Files scanned: {report.scanned_files} "
              f"(skipped {report.skipped_files})")
        print(f"  Unique findings: {len(aggregate_findings(report.findings))}")
    else:
        if verbose >= 1 and out_format == "text":
            print()
        print(rendered)

    if exit_code == EXIT_SUCCESS and args.fail_on_findings and report.findings:
        exit_code = EXIT_FINDINGS
    return exit_code


if __name__ == "__main__":
    if sys_version_info < (3, 12):
        print("Python 3.12 or newer is required.", file=sys_stderr)
        sys_exit(EXIT_ERROR)
    sys_exit(main())
