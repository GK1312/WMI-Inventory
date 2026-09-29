from __future__ import annotations

import json
import logging
import logging.handlers
import sys
from pathlib import Path

DATA = 15
logging.addLevelName(DATA, 'DATA')

LEVELS: dict[str, int] = {
    'DEBUG': logging.DEBUG,
    'DATA': DATA,
    'INFO': logging.INFO,
    'WARNING': logging.WARNING,
    'ERROR': logging.ERROR,
    'CRITICAL': logging.CRITICAL,
}

def _data(self: logging.Logger, message: str, *args, **kwargs) -> None:
    if self.isEnabledFor(DATA):
        self._log(DATA, message, args, **kwargs)

logging.Logger.data = _data

class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload = {
            'timestamp': self.formatTime(record, '%Y-%m-%dT%H:%M:%S%z'),
            'level': record.levelname,
            'logger': record.name,
            'message': record.getMessage(),
        }
        if record.exc_info:
            payload['exc_info'] = self.formatException(record.exc_info)
        return json.dumps(payload)


_HUMAN_FORMAT = '%(asctime)s %(levelname)-7s %(name)s: %(message)s'

_configured = False

def setup_logging(settings, *, force: bool = False) -> None:
    global _configured
    if _configured and not force:
        return
    _configured = True

    root = logging.getLogger()
    root.handlers.clear()

    if not settings.logging_enabled:
        root.addHandler(logging.NullHandler())
        root.setLevel(logging.CRITICAL + 1)
        return

    level = LEVELS.get(settings.log_level, logging.INFO)
    root.setLevel(level)

    if settings.app_env == 'development':
        handler = logging.StreamHandler(sys.stderr)
        handler.setFormatter(logging.Formatter(_HUMAN_FORMAT, datefmt='%H:%M:%S'))
        root.addHandler(handler)
        return

    stream_handler = logging.StreamHandler(sys.stdout)
    stream_handler.setFormatter(JsonFormatter())
    root.addHandler(stream_handler)

    if settings.app_env == 'production':
        log_path = Path(settings.log_file)
        log_path.parent.mkdir(parents=True, exist_ok=True)
        file_handler = logging.handlers.RotatingFileHandler(
            log_path, maxBytes=10_000_000, backupCount=5, encoding='utf-8'
        )
        file_handler.setFormatter(JsonFormatter())
        root.addHandler(file_handler)


def get_logger(name: str) -> logging.Logger:
    return logging.getLogger(name)