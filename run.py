import sys
import logging

from aiohttp.web import run_app

from sqli.app import init as init_app

log = logging.getLogger(__name__)
