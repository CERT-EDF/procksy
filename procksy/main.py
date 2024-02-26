"""Procksy application
"""
from signal import signal, SIGINT, SIGTERM
from getpass import getpass
from argparse import ArgumentParser
from threading import Event
from .proxy import Procksy
from .config import ProcksyConfig
from .logging import LOGGER
from .__version__ import version
from .authenticator import PASSWORD_HASHER


TERM_EVT = Event()


def _sigterm_handler(_signum, _frame):
    print()
    LOGGER.warning("signal caught, please wait for server termination...")
    TERM_EVT.set()


def _cmd_serve(args):
    signal(SIGINT, _sigterm_handler)
    signal(SIGTERM, _sigterm_handler)
    config = ProcksyConfig.from_default_locations()
    config.override(args)
    LOGGER.info("configuration:\n%s", config)
    procksy = Procksy(config=config, term_evt=TERM_EVT)
    procksy.serve()


def _cmd_digest(_):
    print(PASSWORD_HASHER.hash(getpass('secret:')))


def _parse_args():
    parser = ArgumentParser(description=f"Procksy {version}")
    cmd = parser.add_subparsers(dest='cmd', help="Command")
    cmd.required = True
    serve = cmd.add_parser('serve', help="Start serving")
    serve.add_argument(
        '--users',
        metavar='USER_VALUE',
        nargs='+',
        help="Authorized users (username:digest)",
    )
    serve.add_argument(
        '--client-filter',
        help="Filter clients (mode:value,value,value)",
    )
    serve.add_argument(
        '--target-filter',
        help="Filter targets (mode:value,value,value)",
    )
    serve.add_argument('--bind-addr', help="Bind address")
    serve.add_argument('--bind-port', type=int, help="Bind port")
    serve.add_argument('--buffer-size', type=int, help="Buffer size")
    serve.add_argument(
        '--max-threads', type=int, help="Maximum concurrent connections"
    )
    serve.add_argument('--sock-timeout', type=int, help="Socket timeout")
    serve.set_defaults(func=_cmd_serve)
    digest = cmd.add_parser(
        'digest', help="Generate argon2id digest for given secret"
    )
    digest.set_defaults(func=_cmd_digest)
    return parser.parse_args()


def app():
    """Application entrypoint"""
    LOGGER.info("Procksy %s", version)
    args = _parse_args()
    args.func(args)


if __name__ == '__main__':
    app()
