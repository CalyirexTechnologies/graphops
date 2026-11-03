"""Exports in formats other tools already read.

Four, each chosen because something downstream consumes it without a custom
parser:

  * **STIX 2.1** for threat intelligence platforms and MISP.
  * **SARIF 2.1.0** because GitHub code scanning and most IDEs render it, so
    an attack path can appear in the same queue as a static-analysis finding.
  * **OSCAL** assessment results, which is what a compliance team's GRC tool
    expects rather than a PDF.
  * **CSV**, because the person who has to act on this often works in a
    spreadsheet and pretending otherwise helps nobody.

None of these invent fields. Where a format has no place for something, it is
left out rather than stuffed into a vendor extension that no consumer reads.
"""
from __future__ import annotations

from .csv_export import to_csv
from .oscal import to_oscal
from .sarif import to_sarif
from .stix import to_stix

EXPORTERS = {'stix': to_stix, 'sarif': to_sarif, 'oscal': to_oscal,
             'csv': to_csv}


def export_estate(estate, *, fmt: str = 'stix') -> dict:
    try:
        exporter = EXPORTERS[fmt]
    except KeyError as exc:
        raise ValueError('unknown export format %r; known: %s'
                         % (fmt, ', '.join(sorted(EXPORTERS)))) from exc
    return exporter(estate)


__all__ = ['export_estate', 'EXPORTERS', 'to_stix', 'to_sarif', 'to_oscal',
           'to_csv']
