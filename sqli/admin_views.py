import os
import pickle
import base64
import logging
import subprocess

import requests as http_requests
from aiohttp.web import Request, HTTPFound, Response
from aiohttp.web_exceptions import HTTPNotFound
from aiohttp_jinja2 import template
from aiohttp_session import get_session

from sqli.utils.auth import get_auth_user

log = logging.getLogger(__name__)


@template('admin.jinja2')
async def admin_panel(request: Request):
    """Admin panel landing page with tools."""
    auth_user = await get_auth_user(request)
    return {'auth_user': auth_user, 'results': None}


async def export_data(request: Request):
    """VULNERABILITY: Command Injection
    User-controlled input is passed directly to os.system() and subprocess
    with shell=True, allowing arbitrary command execution.
    """
    data = await request.post()
    table_name = data.get('table_name', 'students')
    fmt = data.get('format', 'csv')

    # VULN: Command injection via string concatenation into os.system()
    export_cmd = f"pg_dump -t {table_name} --format={fmt} sqli"
    log.info(f"Running export command: {export_cmd}")
    os.system(export_cmd)

    # VULN: Also vulnerable via subprocess with shell=True
    cleanup_cmd = f"rm -f /tmp/export_{table_name}.bak"
    result = subprocess.run(cleanup_cmd, shell=True, capture_output=True, text=True)

    return Response(
        text=f"Export completed for table: {table_name}",
        content_type='text/plain'
    )


async def read_file(request: Request):
    """VULNERABILITY: Path Traversal
    User-controlled filename is concatenated to a base path without any
    sanitization, allowing ../../etc/passwd style attacks.
    """
    filename = request.query.get('filename', '')

    if not filename:
        return Response(text="No filename provided", status=400)

    # VULN: Path traversal — no sanitization of ".." sequences
    base_dir = "/app/data"
    file_path = os.path.join(base_dir, filename)

    try:
        with open(file_path, 'r') as f:
            content = f.read()
        return Response(text=content, content_type='text/plain')
    except FileNotFoundError:
        return Response(text=f"File not found: {filename}", status=404)
    except Exception as e:
        return Response(text=f"Error reading file: {str(e)}", status=500)


async def fetch_url(request: Request):
    """VULNERABILITY: Server-Side Request Forgery (SSRF)
    User-supplied URL is fetched directly with no allowlist or validation,
    allowing access to internal services, cloud metadata endpoints, etc.
    """
    data = await request.post()
    url = data.get('url', '')

    if not url:
        return Response(text="No URL provided", status=400)

    # VULN: SSRF — fetching arbitrary user-provided URL with no validation
    try:
        log.info(f"Fetching URL: {url}")
        resp = http_requests.get(url, timeout=10)
        return Response(
            text=resp.text,
            content_type=resp.headers.get('Content-Type', 'text/plain')
        )
    except http_requests.exceptions.RequestException as e:
        return Response(text=f"Error fetching URL: {str(e)}", status=502)


async def import_data(request: Request):
    """VULNERABILITY: Insecure Deserialization
    User-supplied base64 data is decoded and passed directly to pickle.loads(),
    allowing arbitrary code execution via crafted pickle payloads.
    """
    data = await request.post()
    payload = data.get('payload', '')

    if not payload:
        return Response(text="No payload provided", status=400)

    # VULN: Insecure deserialization via pickle.loads on user input
    try:
        raw_data = base64.b64decode(payload)
        deserialized = pickle.loads(raw_data)
        log.info(f"Successfully deserialized data: {type(deserialized)}")
        return Response(
            text=f"Import successful. Loaded {type(deserialized).__name__} object.",
            content_type='text/plain'
        )
    except Exception as e:
        return Response(text=f"Import failed: {str(e)}", status=400)
