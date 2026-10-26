#!/usr/bin/env python3

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
  BAN_FILE = _env.get("BAN_FILE","")
  LOG_FILE = _env.get("LOG_FILE","fail2ban-connector.log")
  RELOAD_MARKER = _env.get("RELOAD_MARKER","/run/fail2ban-nginx-connector.reload")
  LOCK_FILE = _env.get("LOCK_FILE","/run/fail2ban-nginx-connector.lock")
  TELEGRAM_TOKEN = _env.get("TELEGRAM_TOKEN","")
  TELEGRAM_CHAT_ID = _env.get("TELEGRAM_CHAT_ID","")
  SERVER_NAME = _env.get("SERVER_NAME","")
  NGINX_RELOAD_REPORT = int(_env.get("NGINX_RELOAD_REPORT","0"))
  ACTIONS_REPORT = int(_env.get("ACTIONS_REPORT","1"))
  NGINX_BIN = _env.get("NGINX_BIN","/usr/sbin/nginx")
  if not BAN_FILE:
    sys.exit(f"Variable BAN_FILE is not set in .env file!")
except KeyError as e:
  sys.exit(f"Missing variable {e} in {ENV_FILE}")
except ValueError as e:
  sys.exit(f"Invalid value in {ENV_FILE}: {e}")

def log(message):
  timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
  with open(LOG_FILE, "a", encoding="utf-8") as f:
    f.write(f"{timestamp} {message}\n")

def telegram(message, title):
  if not TELEGRAM_CHAT_ID or not TELEGRAM_TOKEN:
    return
  url = f"https://api.telegram.org/bot{TELEGRAM_TOKEN}/sendMessage"
  payload = json.dumps({"chat_id": TELEGRAM_CHAT_ID, "text": f"{title} ({SERVER_NAME})\n{message}"}).encode()
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
      if ACTIONS_REPORT == 1:
        telegram(f"{name} Ban of IP {ip} - this IP already exists!", "🏮Fail2ban-Nginx")
      log(f"{name} Ban of IP {ip} - this IP already exists!")
      return
    with open(BAN_FILE, "a", encoding="utf-8") as f:
      if lines and not lines[-1].endswith("\n"):
        f.write("\n")
      f.write(f"{ip} 1;\n")
    create_reload_marker()
  log(f"{name} Added {ip} to {BAN_FILE}, reload scheduled")
  if ACTIONS_REPORT == 1:
    telegram(f"{name} Banned IP {ip}", "👮Fail2ban-Nginx")

def unban(ip, name):
  with lock():
    lines = read_ban_lines()
    remaining = [line for line in lines if line_ip(line) != ip]
    if len(remaining) == len(lines):
      if ACTIONS_REPORT == 1:
        telegram(f"{name} Unban of IP {ip} - this IP not exists in the ban config!", "🏮Fail2ban-Nginx")
      log(f"{name} Unban of IP {ip} - this IP not exists in the ban config!")
      return
    with open(BAN_FILE, "w", encoding="utf-8") as f:
      f.writelines(remaining)
    create_reload_marker()
  log(f"{name} Removed {ip} from {BAN_FILE}, reload scheduled")
  if ACTIONS_REPORT == 1:
    telegram(f"{name} IP {ip} was unbanned", "🏃Fail2ban-Nginx")

def run_nginx(args):
  try:
    return subprocess.run([NGINX_BIN, *args], capture_output=True, text=True, timeout=30)
  except (subprocess.TimeoutExpired, OSError) as e:
    return subprocess.CompletedProcess(args, 1, "", str(e))

def reload_nginx():
  """Reload nginx if the reload marker exists, then remove the marker."""
  with lock():
    if not os.path.exists(RELOAD_MARKER):
      return 0
    os.remove(RELOAD_MARKER)
    test = run_nginx(["-t"])
    if test.returncode != 0:
      create_reload_marker()
      log(f"ERROR: nginx test failed: {test.stderr.strip()}")
      telegram(f"Reload skipped - nginx test failed:\n{test.stderr.strip()[-500:]}", "🚨Fail2ban-Nginx")
      return 1
    result = run_nginx(["-s", "reload"])
    if result.returncode != 0:
      create_reload_marker()
      log(f"ERROR: nginx reload failed: {result.stderr.strip()}")
      telegram(f"Nginx reload failed:\n{result.stderr.strip()[-500:]}", "🚨Fail2ban-Nginx")
      return 1
  log("Nginx reloaded")
  if NGINX_RELOAD_REPORT == 1:
    telegram("Nginx reloaded", "♻Fail2ban-Nginx")
  return 0

def show_current_config():
  print(f"BAN_FILE = {BAN_FILE}")
  print(f"LOG_FILE = {LOG_FILE}")
  print(f"RELOAD_MARKER = {RELOAD_MARKER}")
  print(f"LOCK_FILE = {LOCK_FILE}")
  print(f"TELEGRAM_TOKEN = {TELEGRAM_TOKEN}")
  print(f"TELEGRAM_CHAT_ID = {TELEGRAM_CHAT_ID}")
  print(f"SERVER_NAME = {SERVER_NAME}")
  print(f"NGINX_RELOAD_REPORT = {NGINX_RELOAD_REPORT}")
  print(f"NGINX_BIN = {NGINX_BIN}")
  print(f"ACTIONS_REPORT = {ACTIONS_REPORT}")

def main():
  parser = argparse.ArgumentParser(description="Fail2ban -> nginx ban list connector")
  sub = parser.add_subparsers(dest="action", required=True)
  for action in ("ban", "unban"):
    p = sub.add_parser(action)
    p.add_argument("ip")
    p.add_argument("name", nargs="?", default="unknown")
  sub.add_parser("reload", help="reload nginx if a reload marker exists")
  sub.add_parser("show", help="shows current config variables")
  args = parser.parse_args()
  if args.action == "ban":
    ban(args.ip, args.name or "unknown")
  elif args.action == "unban":
    unban(args.ip, args.name or "unknown")
  elif args.action == "reload":
    return reload_nginx()
  elif args.action == "show":
    return show_current_config()
  return 0

if __name__ == "__main__":
  sys.exit(main())
