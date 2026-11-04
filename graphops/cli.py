"""Command line entry point.

`python3 -m graphops.cli <command>`, or `graphops <command>` once installed.

Commands exist for the things an operator actually does: generate a key,
bootstrap the first tenant, run the connectors, serve the API, verify the
audit chain, and export. Nothing here is a thin wrapper over a single
function call that the operator could run themselves.
"""
from __future__ import annotations

import argparse
import json
import secrets
import sys


def _settings(allow_generated: bool = False):
    from .config import ConfigError, load_settings
    try:
        return load_settings(allow_generated_key=allow_generated)
    except ConfigError as exc:
        print('configuration error: %s' % exc, file=sys.stderr)
        raise SystemExit(2) from exc


def _database(settings):
    from .store.db import Database
    return Database(settings.database_path)


def cmd_keygen(args) -> int:
    """Print a signing key. Never writes it anywhere."""
    print(secrets.token_urlsafe(48))
    print('\nSet it in the environment, not in a file in the repo:\n'
          '  export GRAPHOPS_SIGNING_KEY=<the value above>', file=sys.stderr)
    return 0


def cmd_bootstrap(args) -> int:
    """Create the first organization and its owner."""
    from .identity.service import IdentityService
    settings = _settings()
    db = _database(settings)
    identity = IdentityService(db, settings)

    if identity.organization_by_slug(args.slug):
        print('organization %r already exists' % args.slug, file=sys.stderr)
        return 1

    password = args.password or secrets.token_urlsafe(18)
    org = identity.create_organization(slug=args.slug, name=args.name or args.slug)
    identity.create_user(organization_id=org['id'], email=args.email,
                         password=password, roles=['owner'])
    print(json.dumps({'organization': org['slug'], 'owner': args.email}, indent=2))
    if not args.password:
        # Printed to stderr so a piped stdout stays machine-readable and the
        # password does not land in a file by accident.
        print('\ngenerated owner password: %s' % password, file=sys.stderr)
    return 0


def cmd_ingest(args) -> int:
    """Run the connectors and write the resulting estate."""
    from .connectors import registry, resolve
    result = registry.ingest(args.connectors or None, mode=args.mode)
    resolved = resolve.resolve(result.estate)

    for run in result.runs:
        print('%-14s %-8s %4d nodes %4d edges  %s'
              % (run.connector, run.status, run.nodes, run.edges,
                 run.error or ''))
    merged = resolved.get('resolution', {})
    print('\n%d nodes, %d edges after resolving %d duplicate entities'
          % (len(resolved['nodes']), len(resolved['edges']),
             merged.get('merged', 0)))

    if args.out:
        with open(args.out, 'w', encoding='utf-8') as handle:
            json.dump(resolved, handle, indent=2)
        print('wrote %s' % args.out)
    return 0 if result.status != 'failed' else 1


def cmd_analyse(args) -> int:
    """Print every answer for an estate."""
    from . import analysis
    from .connectors import registry, resolve

    if args.estate:
        estate = analysis.Estate.from_file(args.estate)
    else:
        estate = analysis.Estate(resolve.resolve(registry.ingest().estate))

    from .findings import derive
    produced = derive(estate)
    print('%d findings\n' % len(produced))
    for finding in produced:
        print('[%-8s] %s' % (finding['severity'], finding['title']))
        print('           %s\n' % finding['remediation'])
    return 0


def cmd_containment(args) -> int:
    """Rank the single cuts by what each was measured to buy."""
    from . import analysis
    from .connectors import registry, resolve

    if args.estate:
        estate = analysis.Estate.from_file(args.estate)
    else:
        estate = analysis.Estate(resolve.resolve(registry.ingest().estate))

    result = analysis.containment(estate)
    if not result.get('reachable'):
        print(result.get('why', 'Nothing to contain.'))
        return 0

    print('%d routes reach %d crown jewels, cheapest at effort %.1f\n'
          % (result['routes_before'], len(result['crown_jewels_at_risk']),
             result['cheapest_before']))
    print('Each line below was measured by making the cut and running the '
          'search again.\n')

    for index, option in enumerate(result['options'], start=1):
        protects = [j['key'] for j in option['crown_jewels_cut_off']]
        print('%d. %s' % (index, option['cut']['action']))
        print('   removes %d of %d routes'
              % (option['routes_removed'], option['routes_before']), end='')
        if option['fully_contained']:
            print(', leaving no route at all')
        elif protects:
            print(', and puts %s out of reach' % ', '.join(protects))
        else:
            print(', every crown jewel still reachable')
        if option['cheapest_after'] is not None:
            print('   attacker effort for what is left: %.1f -> %.1f'
                  % (option['cheapest_before'], option['cheapest_after']))
        if option['kind'] == 'entitlement':
            print('   this one is a grant nobody has used, so no downtime')
        print()
    return 0


def cmd_export(args) -> int:
    from . import analysis
    from .connectors import registry, resolve
    from .exporters import export_estate

    estate = (analysis.Estate.from_file(args.estate) if args.estate
              else analysis.Estate(resolve.resolve(registry.ingest().estate)))
    payload = export_estate(estate, fmt=args.format)
    text = (payload['content'] if args.format == 'csv'
            else json.dumps(payload, indent=2))
    if args.out:
        with open(args.out, 'w', encoding='utf-8') as handle:
            handle.write(text)
        print('wrote %s' % args.out)
    else:
        print(text)
    return 0


def cmd_verify_audit(args) -> int:
    """Recompute the audit hash chain."""
    from .audit.chain import AuditLog
    settings = _settings()
    report = AuditLog(_database(settings)).verify_chain(
        expected_head=args.expected_head)
    print(json.dumps(report, indent=2))
    return 0 if report['valid'] else 1


def cmd_serve(args) -> int:
    """Run the API."""
    import uvicorn

    from . import analysis
    from .api.app import create_app
    from .connectors import registry, resolve

    settings = _settings()
    db = _database(settings)
    estate = analysis.Estate(resolve.resolve(registry.ingest().estate))
    app = create_app(settings=settings, db=db, estate_provider=lambda: estate)
    # 127.0.0.1 by default. Binding 0.0.0.0 is an explicit choice an operator
    # makes, not something a default does on their behalf.
    uvicorn.run(app, host=args.host, port=args.port, log_level='info')
    return 0


def cmd_demo(args) -> int:
    """Run the engine demo against the hand-authored estate."""
    from .demo import main as demo_main
    demo_main()
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog='graphops',
        description='Security telemetry as a graph.')
    subparsers = parser.add_subparsers(dest='command', required=True)

    subparsers.add_parser('keygen', help='print a new signing key'
                          ).set_defaults(func=cmd_keygen)

    bootstrap = subparsers.add_parser('bootstrap',
                                      help='create the first tenant and owner')
    bootstrap.add_argument('--slug', required=True)
    bootstrap.add_argument('--email', required=True)
    bootstrap.add_argument('--name', default='')
    bootstrap.add_argument('--password', default='',
                           help='omit to have one generated')
    bootstrap.set_defaults(func=cmd_bootstrap)

    ingest = subparsers.add_parser('ingest', help='run the connectors')
    ingest.add_argument('connectors', nargs='*')
    ingest.add_argument('--mode', choices=('replay', 'live'), default='replay')
    ingest.add_argument('--out', default='')
    ingest.set_defaults(func=cmd_ingest)

    analyse = subparsers.add_parser('analyse', help='print the findings')
    analyse.add_argument('--estate', default='')
    analyse.set_defaults(func=cmd_analyse)

    contain = subparsers.add_parser(
        'containment', help='rank single cuts by what each one is measured to buy')
    contain.add_argument('--estate', default='')
    contain.set_defaults(func=cmd_containment)

    export = subparsers.add_parser('export', help='export the estate')
    export.add_argument('--format', choices=('stix', 'sarif', 'oscal', 'csv'),
                        default='stix')
    export.add_argument('--estate', default='')
    export.add_argument('--out', default='')
    export.set_defaults(func=cmd_export)

    verify = subparsers.add_parser('verify-audit',
                                   help='recompute the audit hash chain')
    verify.add_argument('--expected-head', default=None,
                        help='an anchored head hash published elsewhere')
    verify.set_defaults(func=cmd_verify_audit)

    serve = subparsers.add_parser('serve', help='run the API')
    serve.add_argument('--host', default='127.0.0.1')
    serve.add_argument('--port', type=int, default=8000)
    serve.set_defaults(func=cmd_serve)

    subparsers.add_parser('demo', help='run the engine demo'
                          ).set_defaults(func=cmd_demo)
    return parser


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == '__main__':
    raise SystemExit(main())
