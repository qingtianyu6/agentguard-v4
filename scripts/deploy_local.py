#!/usr/bin/env python3
"""Run a loopback-only AgentGuard demonstration deployment."""
import argparse
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import time
from urllib.request import urlopen

ROOT = Path(__file__).resolve().parents[1]
STATE = ROOT / 'runtime' / 'local'
PORT_API = 8000
PORT_WEB = 5173


def alive(pid):
    try:
        os.kill(pid, 0)
        return True
    except (OSError, TypeError):
        return False


def read_pid(name):
    try:
        return int((STATE / f'{name}.pid').read_text().strip())
    except (OSError, ValueError):
        return None


def check(url, expected):
    try:
        with urlopen(url, timeout=2) as response:
            return response.status == 200 and expected in response.read(200000).decode()
    except Exception:
        return False


def stop():
    for name in ('web', 'api'):
        pid = read_pid(name)
        if pid and alive(pid):
            os.kill(pid, signal.SIGTERM)
        (STATE / f'{name}.pid').unlink(missing_ok=True)


def start():
    if any(alive(read_pid(name)) for name in ('api', 'web')):
        raise SystemExit('Existing deployment found; run stop first')
    if not (ROOT / 'frontend' / 'dist' / 'index.html').exists():
        raise SystemExit('Build frontend first: cd frontend && npm ci && npm run build')
    STATE.mkdir(parents=True, exist_ok=True)
    env = os.environ.copy()
    env['DATABASE_URL'] = f"sqlite:///{STATE / 'agentguard.db'}"
    env['AGENTGUARD_SECURITY_PROFILE'] = 'sandbox'
    # Loopback-only sandbox mode is a local demonstration, never a public service.
    env['PYTHONPATH'] = str(ROOT / 'backend')
    commands = {
        'api': [sys.executable, '-m', 'uvicorn', 'app.main:app', '--host', '127.0.0.1', '--port', str(PORT_API)],
        'web': [sys.executable, '-m', 'http.server', str(PORT_WEB), '--bind', '127.0.0.1', '--directory', str(ROOT / 'frontend' / 'dist')],
    }
    try:
        for name, command in commands.items():
            log = open(STATE / f'{name}.log', 'ab')
            try:
                process = subprocess.Popen(command, cwd=ROOT, env=env, stdout=log, stderr=subprocess.STDOUT, start_new_session=True)
            finally:
                log.close()
            (STATE / f'{name}.pid').write_text(str(process.pid))
        for _ in range(40):
            if check(f'http://127.0.0.1:{PORT_API}/api/v1/health', '"status":"ok"') and check(f'http://127.0.0.1:{PORT_WEB}/', 'AgentGuard'):
                print(json.dumps({'status': 'running', 'api': f'http://127.0.0.1:{PORT_API}', 'web': f'http://127.0.0.1:{PORT_WEB}', 'profile': 'sandbox-local'}))
                return
            if not all(alive(read_pid(name)) for name in commands):
                break
            time.sleep(.25)
        raise RuntimeError(f'Startup failed; inspect {STATE}/*.log')
    except Exception:
        stop()
        raise


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('command', choices=['start', 'stop', 'status'])
    command = parser.parse_args().command
    if command == 'start':
        start()
    elif command == 'stop':
        stop()
        print('Stopped local deployment')
    else:
        print(json.dumps({'api': alive(read_pid('api')) and check(f'http://127.0.0.1:{PORT_API}/api/v1/health', '"status":"ok"'), 'web': alive(read_pid('web')) and check(f'http://127.0.0.1:{PORT_WEB}/', 'AgentGuard')}))
