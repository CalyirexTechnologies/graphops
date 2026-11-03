"""Prometheus metrics, rendered from a small in-process registry.

No client library. The exposition format is a documented text format and
emitting it correctly is forty lines, which is less than the dependency
costs in a container that otherwise needs nothing but FastAPI.

The rules the format imposes, and which the renderer enforces rather than
hoping callers remember: a metric name appears in exactly one HELP and one
TYPE line, label values escape backslash, newline and quote, and a counter
never decreases.
"""
from __future__ import annotations

import threading
import time

_LOCK = threading.Lock()
_COUNTERS: dict[tuple[str, tuple], float] = {}
_GAUGES: dict[tuple[str, tuple], float] = {}
_HELP: dict[str, str] = {}
_TYPES: dict[str, str] = {}

_STARTED = time.time()


def _key(name: str, labels: dict | None) -> tuple[str, tuple]:
    items = tuple(sorted((str(k), str(v)) for k, v in (labels or {}).items()))
    return name, items


def counter(name: str, *, help: str = '', labels: dict | None = None,
            amount: float = 1.0) -> None:
    if amount < 0:
        raise ValueError('a counter cannot decrease')
    with _LOCK:
        _HELP.setdefault(name, help or name)
        _TYPES[name] = 'counter'
        key = _key(name, labels)
        _COUNTERS[key] = _COUNTERS.get(key, 0.0) + amount


def gauge(name: str, value: float, *, help: str = '',
          labels: dict | None = None) -> None:
    with _LOCK:
        _HELP.setdefault(name, help or name)
        _TYPES[name] = 'gauge'
        _GAUGES[_key(name, labels)] = float(value)


def _escape(value: str) -> str:
    return (str(value).replace('\\', '\\\\')
            .replace('\n', '\\n').replace('"', '\\"'))


def _format(name: str, labels: tuple, value: float) -> str:
    if labels:
        rendered = ','.join('%s="%s"' % (k, _escape(v)) for k, v in labels)
        return '%s{%s} %g' % (name, rendered, value)
    return '%s %g' % (name, value)


def render() -> str:
    """The exposition payload."""
    gauge('graphops_uptime_seconds', time.time() - _STARTED,
          help='Seconds since this process started.')
    with _LOCK:
        names = sorted(set(_TYPES))
        lines: list[str] = []
        for name in names:
            lines.append('# HELP %s %s' % (name, _HELP.get(name, name)))
            lines.append('# TYPE %s %s' % (name, _TYPES[name]))
            source = _COUNTERS if _TYPES[name] == 'counter' else _GAUGES
            for (metric, labels), value in sorted(source.items()):
                if metric == name:
                    lines.append(_format(metric, labels, value))
        return '\n'.join(lines) + '\n'


def reset() -> None:
    """For tests. Never called by the application."""
    with _LOCK:
        _COUNTERS.clear()
        _GAUGES.clear()
        _HELP.clear()
        _TYPES.clear()
