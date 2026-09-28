# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project status

This is an early-stage Python scaffold (PyCharm project) for a WMI-based inventory tool. Most of it is still a stub:

- `app/main.py` is an argparse command-line tool: `main.py [START END] [--hosts]` (prompts for any address that's missing). It prints a JSON array to stdout — CIDR network strings by default, or individual IP address strings with `--hosts` — and a one-line count summary to stderr. Exits with 1 on invalid input.
- `app/utils/iprange.py`, `app/utils/{query_responses,field_validators,other_responses}.py`, `app/core/{errors,logging}.py`, and `app/config.py` are the only implemented modules (see architecture below).
- `app/celery_app.py` and `app/core/security.py` are empty placeholders.

On this machine `python` is the Microsoft Store stub, not a real interpreter. Use the project venv (below), or the `py` launcher to create it.

There's no test suite, no linter config, and no git repository yet. `requirements.txt` has one dependency, `python-dotenv` (added for `app/config.py`'s `.env` loading) — otherwise the app uses only the standard library (a Postgres/`psycopg` integration was explored and then intentionally removed; only the response-shaping utilities below remain). A `.env` with development defaults is already checked in, so no setup is required to import `app/config.py`; every value also has an in-code default, so an absent or partial `.env` still works. Copy `.env.example` if you want to start from a clean template instead.

## Environment

```sh
py -3.14 -m venv .venv                                   # one-time setup (project root)
.venv/Scripts/python.exe -m pip install -r requirements.txt
.venv/Scripts/python.exe app/main.py 192.168.1.1 192.168.1.254
.venv/Scripts/python.exe app/main.py --hosts 192.168.1.1 192.168.1.254
```

Run scripts as `app/<file>.py` (not with `-m`), because modules import each other relative to `app/` (e.g. `from utils.iprange import ...`). There are no `__init__.py` files anywhere under `app/`; `utils` and `core` work as implicit namespace packages, importable as `utils.<module>` / `core.<module>` from anywhere as long as `app/` is on `sys.path` (true automatically when running `app/main.py` as a script).

To exercise `app/core/logging.py`'s environment branching ad hoc (it isn't wired into `main.py` — see below), override the `.env` values on the command line, e.g. from `app/`:
```sh
../.venv/Scripts/python.exe -c "from config import load_settings; from core.logging import setup_logging, get_logger; setup_logging(load_settings()); get_logger('x').info('hi')"
```
with `APP_ENV=staging`, `APP_ENV=production LOG_FILE=...`, or `LOGGING_ENABLED=false` set in the environment first, to see JSON-to-stdout, the rotating file handler, or silence respectively.

## Architecture

- **`app/celery_app.py`**: still an empty placeholder — inferred from the file layout to be a Celery app for running WMI queries against hosts as background tasks.
- **`app/config.py`**: loads `.env` (via `python-dotenv`'s `load_dotenv()`) and exposes a module-level `settings` singleton (`load_settings()` called at import time) — a frozen `Settings` dataclass with `app_env`, `logging_enabled`, `log_level`, `log_file`. `APP_ENV` must be one of `development`/`staging`/`production` and `LOG_LEVEL` must be one of `core.logging.LEVELS`; either being invalid raises `core.errors.StrictError` (a config error, same category as the response-builder dispatch errors below) at import time — there is no fallback-to-default for a *present but invalid* value, only for a *missing* one. `LOGGING_ENABLED` accepts `1/true/yes/on` (case-insensitive) as truthy, anything else (or unset, defaulting to `True`) otherwise.
- **`app/core/`**: cross-cutting concerns. `errors.py` and `logging.py` are implemented — see below; `security.py` is an empty placeholder (previously held credential storage).
- **`app/core/errors.py`**: the app's error hierarchy. `Severity` is an `IntEnum` — `MINOR=10 < WARNING=20 < VALIDATION=30 < STRICT=40` — gapped so new severities can be inserted later without renumbering. `AppError(message, *, field=None)` is the base exception (`field` is optional context: which field/input triggered it). One subclass per severity — `MinorError`, `WarningError`, `ValidationError`, `StrictError` — each just overrides the class-level `severity` attribute, so call sites can either catch a specific kind (`except ValidationError:`) or branch generically on `err.severity`. To add a new kind: add a `Severity` member (using a free value between existing gaps, or extend upward) and a one-line `AppError` subclass. `SecurityError` (defined here, subclassing `StrictError` directly) shows the other extension path: subclass an existing severity class to add a domain-specific kind that inherits that severity without repeating it — currently unused now that `security.py` (its only caller) has been emptied. There is deliberately no logging/handling behavior tying `AppError` to `core/logging.py` yet (no log-and-continue-vs-raise policy) — the two modules are independent so far.
- **`app/core/logging.py`**: global logging setup, driven entirely by an `app.config.Settings` passed into `setup_logging(settings, *, force=False)` (idempotent — a second call is a no-op unless `force=True`, so it's safe to call from more than one entrypoint). Defines a custom `DATA = 15` level (between `DEBUG`=10 and `INFO`=20, registered via `logging.addLevelName` and a `Logger.data(...)` method patched onto the stdlib `Logger` class) for verbose structured payloads — raw query results, full response dicts — that are noisier than `INFO` but not a full execution trace; `LEVELS` maps all six level names (`DEBUG`/`DATA`/`INFO`/`WARNING`/`ERROR`/`CRITICAL`) to their numeric values. Behavior branches on `settings.logging_enabled` and `settings.app_env`: disabled → a `NullHandler` and level set above `CRITICAL` (fully silent); `development` → human-readable text to **stderr**; `staging`/`production` → structured JSON (`JsonFormatter`) to **stdout**, and `production` additionally adds a `RotatingFileHandler` (10MB × 5 backups) writing JSON to `settings.log_file`. **Not wired into `app/main.py`**: `main.py`'s documented contract is a clean JSON array on stdout plus a one-line summary on stderr, and the staging/production JSON-to-stdout behavior above would interleave log lines into that same stdout stream and break it for any consumer parsing the array. `setup_logging`/`get_logger` are built for a future entrypoint that doesn't share that stdout contract (the Celery worker in `celery_app.py`, once it exists) — call `setup_logging(settings)` there, not in `main.py`.
- **`app/core/security.py`**: empty placeholder. Previously held credential storage for WMI scan auth (a `Credential` frozen dataclass plus `store_credential`/`get_credential` backed by an in-memory dict, raising `SecurityError` on a missed lookup) — emptied deliberately; nothing else in the codebase imported it.
- **`app/utils/iprange.py`**:
  - `expand_ranges(start, end)` turns an inclusive IPv4 start/end pair into the smallest list of CIDR networks that covers it (`ipaddress.summarize_address_range`). A bad value raises `ValueError`; the wrong type raises `TypeError`.
  - `expand_hosts(networks)` flattens a `list[IPv4Network]` (e.g. from `expand_ranges`) back into the individual `IPv4Address`es it covers. It iterates each network directly rather than using `.hosts()`, so network/broadcast addresses are included — this is a scan range, not a subnet, so every address in the original inclusive range must round-trip.
- **`app/utils/field_validators.py`**: reusable, per-field validation helpers shared across response builders. `validate_inet` / `validate_bool` / `validate_str(value, field_name, default=OMIT, required=False)` each type-check a value — raising `core.errors.ValidationError` (with `.field` set to `field_name`) on the wrong type, and `validate_inet` also on a string that isn't a valid IP address — and resolve missing values one of three ways depending on the arguments passed at the call site:
  - `required=True` → raise `ValidationError` if the field is missing.
  - `default=<value>` → fill in `<value>` if missing.
  - neither passed → the field resolves to the `OMIT` sentinel, meaning "drop this key from the response entirely." `drop_omitted(dict)` filters those out and is applied at the end of every response builder.
- **`app/utils/query_responses.py`**: shapes raw data into a dict ready for a specific Postgres table insert. `create_query_response(data, table: ResponseTable)` dispatches (via the `_TABLE_BUILDERS` registry) to a `tb_<table>_response(data)` builder function. Currently only `ResponseTable.TB_SYS_IP_RANGES` → `tb_sys_ip_ranges_response`, a **dummy** schema (no real Postgres schema exists yet — column names/types/requiredness will change): `start_ip`/`end_ip` are required `inet` columns, everything else (`range_enabled`, `range_desc`, `site_id`, `cloud_id`, `scan_engine_id`, `cred_id_range`) is optional and only appears in the output if provided. To add a new table, write a `tb_<name>_response(data)` builder using the `field_validators` helpers and add one entry to `_TABLE_BUILDERS`. Dispatching on an unregistered `table` raises `core.errors.StrictError` — a dispatch/config error, distinct from the per-field `ValidationError`s the builder itself raises via `field_validators`.
- **`app/utils/other_responses.py`**: mirrors `query_responses.py`'s dispatch pattern (`create_other_response(data, kind: ResponseKind)` / `_OTHER_BUILDERS`) for response shapes that aren't a direct table insert, including raising `StrictError` on an unregistered `kind`. Currently an empty scaffold — `ResponseKind` has no members yet.

The code uses built-in generic type hints such as `list[...]` and `X | Y`, so it needs Python 3.10 or newer.
