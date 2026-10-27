#!/usr/bin/env python3

import argparse
import fcntl
import html
import json
import os
import re
import subprocess
import sys
import urllib.error
import urllib.request
from contextlib import contextmanager
from datetime import datetime, timedelta

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
  FAIL2BAN_CLIENT = _env.get("FAIL2BAN_CLIENT","/usr/bin/fail2ban-client")
  STATS_JAILS = [jail.strip() for jail in _env.get("STATS_JAILS","").split(",") if jail.strip()]
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

def telegram(message, title, parse_html=False):
  """Send a message. With parse_html=True the message must be valid Telegram HTML."""
  if not TELEGRAM_CHAT_ID or not TELEGRAM_TOKEN:
    return
  url = f"https://api.telegram.org/bot{TELEGRAM_TOKEN}/sendMessage"
  data = {"chat_id": TELEGRAM_CHAT_ID, "text": f"{title} ({SERVER_NAME})\n{message}"}
  if parse_html:
    data["text"] = f"<b>{html.escape(title)} ({html.escape(SERVER_NAME)})</b>\n{message}"
    data["parse_mode"] = "HTML"
  payload = json.dumps(data).encode()
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

LOG_LINE_RE = re.compile(r"^(\d{4}-\d\d-\d\d \d\d:\d\d:\d\d) (.*)$")
ACTION_RE = re.compile(r"^(\S+) (Added|Removed) \S+ (?:to|from) ")
REPEAT_RE = re.compile(r"^(\S+) Ban of IP \S+ - this IP already exists!")

def collect_stats(hours):
  """Count bans/unbans per jail, reloads and errors from the log for the last `hours` hours."""
  since = datetime.now() - timedelta(hours=hours)
  jails = {}
  totals = {"repeat": 0, "reloads": 0, "errors": 0}
  # Also read the previous rotated log, so a rotation doesn't cut the period in half
  for path in (LOG_FILE + ".1", LOG_FILE):
    try:
      f = open(path, encoding="utf-8", errors="replace")
    except FileNotFoundError:
      continue
    with f:
      for line in f:
        m = LOG_LINE_RE.match(line.rstrip("\n"))
        if not m:
          continue
        try:
          timestamp = datetime.strptime(m.group(1), "%Y-%m-%d %H:%M:%S")
        except ValueError:
          continue
        if timestamp < since:
          continue
        message = m.group(2)
        action = ACTION_RE.match(message)
        if action:
          if STATS_JAILS and action.group(1) not in STATS_JAILS:
            continue
          counts = jails.setdefault(action.group(1), {"bans": 0, "unbans": 0})
          counts["bans" if action.group(2) == "Added" else "unbans"] += 1
        elif REPEAT_RE.match(message):
          totals["repeat"] += 1
        elif message == "Nginx reloaded":
          totals["reloads"] += 1
        elif message.startswith("ERROR:"):
          totals["errors"] += 1
  return {
    "since": since,
    "until": datetime.now(),
    "jails": jails,
    "fail2ban": fail2ban_status(),
    "banned_now": sum(1 for line in read_ban_lines() if line_ip(line)),
    **totals,
  }

def run_fail2ban(args):
  """Return fail2ban-client stdout, or None if it failed (not root, fail2ban stopped, ...)."""
  try:
    result = subprocess.run([FAIL2BAN_CLIENT, *args], capture_output=True, text=True, timeout=15)
  except (subprocess.TimeoutExpired, OSError):
    return None
  return result.stdout if result.returncode == 0 else None

def fail2ban_status():
  """Return {jail: {"banned": n, "failed": n}} with current values, or None if fail2ban is unavailable."""
  output = run_fail2ban(["status"])
  if output is None:
    return None
  m = re.search(r"Jail list:\s*(.*)", output)
  jails = [jail.strip() for jail in m.group(1).split(",") if jail.strip()] if m else []
  if STATS_JAILS:
    jails = [jail for jail in jails if jail in STATS_JAILS]
  result = {}
  for jail in jails:
    output = run_fail2ban(["status", jail])
    if output is None:
      continue
    values = {}
    for key, label in (("banned", "Currently banned"), ("failed", "Currently failed")):
      m = re.search(rf"{label}:\s*(\d+)", output)
      values[key] = int(m.group(1)) if m else 0
    result[jail] = values
  return result

STATS_NAME_WIDTH = 18

def stats_table(stats):
  """Plain-text table: bans/unbans for the period from the log + current banned/failed from fail2ban."""
  f2b = stats["fail2ban"] or {}
  names = set(stats["jails"]) | set(f2b)
  empty = {"bans": 0, "unbans": 0}

  def now(name, key):
    return f2b[name][key] if name in f2b else "-"

  rows = sorted(names, key=lambda name: (-stats["jails"].get(name, empty)["bans"],
                                         -f2b.get(name, {}).get("banned", 0), name))
  width = min(STATS_NAME_WIDTH, max([len("Total")] + [len(name) for name in names]))
  lines = [f"{'':<{width}} {'-period-':>8} {'---now---':>10}",
           f"{'Jail':<{width}} {'Ban':>4} {'Unb':>3} {'Ban':>5} {'Fail':>4}"]
  for name in rows:
    counts = stats["jails"].get(name, empty)
    short = name if len(name) <= width else name[:width - 1] + "~"
    lines.append(f"{short:<{width}} {counts['bans']:>4} {counts['unbans']:>3} "
                 f"{now(name, 'banned'):>5} {now(name, 'failed'):>4}")
  lines.append("-" * (width + 20))
  total_bans = sum(c["bans"] for c in stats["jails"].values())
  total_unbans = sum(c["unbans"] for c in stats["jails"].values())
  total_banned = sum(v["banned"] for v in f2b.values()) if stats["fail2ban"] is not None else "-"
  total_failed = sum(v["failed"] for v in f2b.values()) if stats["fail2ban"] is not None else "-"
  lines.append(f"{'Total':<{width}} {total_bans:>4} {total_unbans:>3} {total_banned:>5} {total_failed:>4}")
  return "\n".join(lines)

def stats_warnings(stats):
  """Problems worth showing next to the numbers."""
  warnings = []
  if stats["fail2ban"] is None:
    warnings.append(f"fail2ban-client is unavailable ({FAIL2BAN_CLIENT}), current values are not shown")
  else:
    # One IP banned by two jails is a single line in BAN_FILE, so fewer lines than bans is normal.
    # More lines than fail2ban bans means entries fail2ban no longer knows about.
    f2b_banned = sum(v["banned"] for v in stats["fail2ban"].values())
    if stats["banned_now"] > f2b_banned:
      warnings.append(f"BAN_FILE has {stats['banned_now']} IPs, but fail2ban has only {f2b_banned} banned - "
                      f"{stats['banned_now'] - f2b_banned} entries may be orphaned")
  return warnings

def stats_period(stats):
  return f"{stats['since']:%d.%m %H:%M} - {stats['until']:%d.%m %H:%M}"

def print_stats(hours):
  stats = collect_stats(hours)
  print(f"Fail2ban-Nginx stats: period = last {hours}h ({stats_period(stats)}), now = current fail2ban state")
  print()
  if stats["jails"] or stats["fail2ban"]:
    print(stats_table(stats))
  else:
    print("No bans or unbans in this period")
  print()
  print(f"In BAN_FILE now:    {stats['banned_now']}")
  print(f"Repeat bans:        {stats['repeat']}")
  print(f"Nginx reloads:      {stats['reloads']}")
  print(f"Errors:             {stats['errors']}")
  for warning in stats_warnings(stats):
    print(f"WARNING: {warning}")
  return 0

def send_stats(hours):
  if not TELEGRAM_CHAT_ID or not TELEGRAM_TOKEN:
    print("Telegram is not configured: set TELEGRAM_TOKEN and TELEGRAM_CHAT_ID in .env")
    return 1
  stats = collect_stats(hours)
  if stats["jails"] or stats["fail2ban"]:
    table = f"<pre>{html.escape(stats_table(stats))}</pre>"
  else:
    table = "<i>No bans or unbans in this period</i>"
  message = (
    f"🗓 Period: last {hours}h, {stats_period(stats)}\n"
    f"⏱ Now: current fail2ban state\n\n"
    f"{table}\n\n"
    f"🚫 In ban list now: <b>{stats['banned_now']}</b>\n"
    f"🔁 Repeat bans: <b>{stats['repeat']}</b>\n"
    f"♻ Nginx reloads: <b>{stats['reloads']}</b>\n"
    f"{'🚨' if stats['errors'] else '✅'} Errors: <b>{stats['errors']}</b>"
  )
  for warning in stats_warnings(stats):
    message += f"\n⚠️ {html.escape(warning)}"
  telegram(message, "📊Fail2ban-Nginx stats", parse_html=True)
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
  print(f"FAIL2BAN_CLIENT = {FAIL2BAN_CLIENT}")
  print(f"STATS_JAILS = {', '.join(STATS_JAILS) or '(all jails)'}")

def main():
  parser = argparse.ArgumentParser(description="Fail2ban -> nginx ban list connector")
  sub = parser.add_subparsers(dest="action", required=True)
  for action in ("ban", "unban"):
    p = sub.add_parser(action)
    p.add_argument("ip")
    p.add_argument("name", nargs="?", default="unknown")
  sub.add_parser("reload", help="reload nginx if a reload marker exists")
  sub.add_parser("show", help="shows current config variables")
  for action, help_text in (("stats", "print ban statistics per jail"),
                            ("stats-report", "send ban statistics per jail to Telegram")):
    p = sub.add_parser(action, help=help_text)
    p.add_argument("--hours", type=int, default=24, help="period in hours (default: 24)")
  args = parser.parse_args()
  if args.action == "ban":
    ban(args.ip, args.name or "unknown")
  elif args.action == "unban":
    unban(args.ip, args.name or "unknown")
  elif args.action == "reload":
    return reload_nginx()
  elif args.action == "show":
    return show_current_config()
  elif args.action == "stats":
    return print_stats(args.hours)
  elif args.action == "stats-report":
    return send_stats(args.hours)
  return 0

if __name__ == "__main__":
  sys.exit(main())
