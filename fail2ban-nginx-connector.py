#!/usr/bin/env python3

"""Fail2ban -> nginx connector.

Usage:
  fail2ban-nginx-connector.py ban <ip> [name]
  fail2ban-nginx-connector.py unban <ip> [name]
  fail2ban-nginx-connector.py reload

ban/unban only edit the ban config and create a reload marker file.
reload checks for the marker and, if present, tests and reloads nginx,
then removes the marker (intended to be run periodically, e.g. from cron/systemd timer).

Settings are read from .env next to this script (path can be overridden
with the FAIL2BAN_CONNECTOR_ENV environment variable).
"""

import argparse
import fcntl
import json
import os
import subprocess
import sys
import urllib.error
import urllib.request
from contextlib import contextmanager
from datetime import datetime

SCRIPT_DIR = os.path.dirname(os.path.realpath(__file__))
ENV_FILE = os.environ.get("FAIL2BAN_CONNECTOR_ENV", os.path.join(SCRIPT_DIR, ".env"))

def load_env(path):
  """Minimal .env parser: KEY=VALUE lines, '#' comments, optional quotes."""
  env = {}
  with open(path, encoding="utf-8") as f:
    for line in f:
      line = line.strip()
      if not line or line.startswith("#") or "=" not in line:
        continue
      key, value = line.split("=", 1)
      value = value.strip()
      if len(value) >= 2 and value[0] == value[-1] and value[0] in "'\"":
        value = value[1:-1]
      env[key.strip()] = value
  return env

try:
  _env = load_env(ENV_FILE)
except FileNotFoundError:
  sys.exit(f"Config file not found: {ENV_FILE}")

try:
  BAN_FILE = _env["BAN_FILE"]
  LOG_FILE = _env["LOG_FILE"]
  RELOAD_MARKER = _env["RELOAD_MARKER"]
  LOCK_FILE = _env["LOCK_FILE"]
  TELEGRAM_TOKEN = _env["TELEGRAM_TOKEN"]
  TELEGRAM_CHAT_ID = _env["TELEGRAM_CHAT_ID"]
  SERVER_NAME = _env["SERVER_NAME"]
  NGINX_RELOAD_REPORT = _env["NGINX_RELOAD_REPORT"]
except KeyError as e:
  sys.exit(f"Missing variable {e} in {ENV_FILE}")

def log(message):
  timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
  with open(LOG_FILE, "a", encoding="utf-8") as f:
    f.write(f"{timestamp} {message}\n")

def telegram(message, title):
  url = f"https://api.telegram.org/bot{TELEGRAM_TOKEN}/sendMessage"
  payload = json.dumps({"chat_id": TELEGRAM_CHAT_ID, "text": f"{title} {SERVER_NAME}\n{message}"}).encode()
  request = urllib.request.Request(url, data=payload, headers={"Content-Type": "application/json"})
  try:
    with urllib.request.urlopen(request, timeout=10):
      pass
  except (urllib.error.URLError, OSError) as e:
    log(f"ERROR: failed to send telegram message: {e}")

@contextmanager
def lock():
  """Serialize concurrent fail2ban actions and reloads."""
  with open(LOCK_FILE, "w") as f:
    fcntl.flock(f, fcntl.LOCK_EX)
    try:
      yield
    finally:
      fcntl.flock(f, fcntl.LOCK_UN)

def read_ban_lines():
  try:
    with open(BAN_FILE, encoding="utf-8") as f:
      return f.readlines()
  except FileNotFoundError:
    return []

def line_ip(line):
  """Return the IP from a line like '1.2.3.4 1;', or None."""
  parts = line.split()
  return parts[0].rstrip(";") if parts else None

def create_reload_marker():
  with open(RELOAD_MARKER, "w"):
    pass

def ban(ip, name):
  with lock():
    lines = read_ban_lines()
    if any(line_ip(line) == ip for line in lines):
      telegram(f"{name} Ban of IP {ip} - this IP already exists!", "🏮Fail2ban-Nginx")
      log(f"{name} Ban of IP {ip} - this IP already exists!")
      return
    with open(BAN_FILE, "a", encoding="utf-8") as f:
      if lines and not lines[-1].endswith("\n"):
        f.write("\n")
      f.write(f"{ip} 1;\n")
    create_reload_marker()
  log(f"{name} Added {ip} to {BAN_FILE}, reload scheduled")
  telegram(f"{name} Banned IP {ip}", "👮Fail2ban-Nginx")

def unban(ip, name):
  with lock():
    lines = read_ban_lines()
    remaining = [line for line in lines if line_ip(line) != ip]
    if len(remaining) == len(lines):
      telegram(f"{name} Unban of IP {ip} - this IP not exists in the ban config!", "🏮Fail2ban-Nginx")
      log(f"{name} Unban of IP {ip} - this IP not exists in the ban config!")
      return
    with open(BAN_FILE, "w", encoding="utf-8") as f:
      f.writelines(remaining)
    create_reload_marker()
  log(f"{name} Removed {ip} from {BAN_FILE}, reload scheduled")
  telegram(f"{name} IP {ip} was unbanned", "🏃Fail2ban-Nginx")

def reload_nginx():
  """Reload nginx if the reload marker exists, then remove the marker."""
  with lock():
    if not os.path.exists(RELOAD_MARKER):
      return 0
    # Remove the marker before reloading so a ban arriving after the
    # reload re-creates it instead of being lost.
    os.remove(RELOAD_MARKER)
    test = subprocess.run(["nginx", "-t"], capture_output=True, text=True)
    if test.returncode != 0:
      create_reload_marker()
      log(f"ERROR: nginx test failed: {test.stderr.strip()}")
      telegram("Reload skipped - nginx test failed", "🏮Fail2ban-Nginx")
      return 1
    result = subprocess.run(["nginx", "-s", "reload"], capture_output=True, text=True)
    if result.returncode != 0:
      create_reload_marker()
      log(f"ERROR: nginx reload failed: {result.stderr.strip()}")
      telegram("Nginx reload failed", "🏮Fail2ban-Nginx")
      return 1
  log("Nginx reloaded")
  if NGINX_RELOAD_REPORT == 1:
    telegram("Nginx reloaded", "♻Fail2ban-Nginx")
  return 0

def main():
  parser = argparse.ArgumentParser(description="Fail2ban -> nginx ban list connector")
  sub = parser.add_subparsers(dest="action", required=True)
  for action in ("ban", "unban"):
    p = sub.add_parser(action)
    p.add_argument("ip")
    p.add_argument("name", nargs="?", default="unknown")
  sub.add_parser("reload", help="reload nginx if a reload marker exists")
  args = parser.parse_args()

  if args.action == "ban":
    ban(args.ip, args.name or "unknown")
  elif args.action == "unban":
    unban(args.ip, args.name or "unknown")
  elif args.action == "reload":
    return reload_nginx()
  return 0

if __name__ == "__main__":
  sys.exit(main())
