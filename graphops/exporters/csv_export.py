"""CSV, for the person who actually has to do the work.

Written with `csv.writer` rather than string joins, because a finding title
containing a comma or a quote is not hypothetical and hand-rolled CSV breaks
on the first one. Fields are also guarded against formula injection: a cell
beginning =, +, - or @ is prefixed with a single quote, since spreadsheet
software executes those on open and a finding title is attacker-influenced
text.
"""
from __future__ import annotations

import csv
import io

COLUMNS = ('fingerprint', 'severity', 'kind', 'title', 'routes', 'target',
           'remediation')

#: Characters that make a spreadsheet treat a cell as a formula.
_FORMULA_PREFIXES = ('=', '+', '-', '@', '\t', '\r')


def _safe(value) -> str:
    text = '' if value is None else str(value)
    if text[:1] in _FORMULA_PREFIXES:
        return "'" + text
    return text


def to_csv(estate) -> dict:
    """Return the CSV as text inside a dict, so every exporter returns JSON."""
    from ..findings import derive

    buffer = io.StringIO()
    writer = csv.writer(buffer, quoting=csv.QUOTE_MINIMAL, lineterminator='\n')
    writer.writerow(COLUMNS)
    rows = 0
    for finding in derive(estate):
        writer.writerow([_safe(finding.get(column)) for column in COLUMNS])
        rows += 1
    return {'format': 'csv', 'rows': rows, 'columns': list(COLUMNS),
            'content': buffer.getvalue()}
