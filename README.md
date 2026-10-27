# Fail2ban-nginx-connector

A small Fail2ban action that blocks IP addresses **in nginx** instead of the firewall.
Banned clients get `444` (connection closed without a response) on every virtual host.

This is useful when nginx sits behind a load balancer or CDN, where firewall bans don't work
because every connection comes from the proxy, and the real client IP is only known to nginx
(via `real_ip`).

## Features

- Adds and removes IPs in an nginx `geo` file (`<ip> 1;` per line).
- **Deferred reload**: `ban`/`unban` only edit the file and drop a marker file.
  A separate `reload` command, run from cron, tests and reloads nginx **once** for any number of changes,
  so a burst of bans doesn't trigger a burst of reloads.
- Runs `nginx -t` before every reload. If the test or the reload fails, the marker is kept and the reload is retried on the next run.
- Telegram notifications for bans, unbans and errors, with optional notifications for successful reloads.
- Daily statistics per jail (no IP addresses), printed in the console or sent to Telegram.
- Safe for parallel runs: Fail2ban can start many actions at once, and a `flock` lock serializes them.
- Single file with no dependencies, only the Python standard library.

## How it works

```
fail2ban ──ban/unban──▶ banned-ip.conf  +  reload marker
                                              │
cron (every minute) ──reload──▶ marker exists? ──▶ nginx -t ──▶ nginx -s reload ──▶ remove marker
```

## Requirements

- Linux, Python 3.7+
- nginx, Fail2ban
- Run as root, because the script writes to `/etc/nginx` and `/run` and reloads nginx.

## Installation

### 1. Script and config

```bash
git clone https://github.com/Xpyctiks/Fail2ban-nginx-connector.git /opt/fail2ban-nginx-connector
cd /opt/fail2ban-nginx-connector
cp .env.example .env
chmod 600 .env          # contains the Telegram bot token
chmod +x fail2ban-nginx-connector.py
touch /etc/nginx/additional-configs/banned-ip.conf
```

Edit `.env` (see [Configuration](#configuration)) and check the result:

```bash
./fail2ban-nginx-connector.py show
```

### 2. nginx

Declare the variable **once** in the `http {}` block (`nginx.conf`):

```nginx
http {
    geo $banned_ip {
        default 0;
        include additional-configs/banned-ip.conf;
    }
    ...
}
```

Create `/etc/nginx/snippets/banned-ip.conf`:

```nginx
if ($banned_ip) {
    return 444;
}
```

Include it in every `server {}` block that should be protected:

```nginx
server {
    listen 443 ssl;
    server_name example.com;
    include snippets/banned-ip.conf;
    ...
}
```

> nginx does not allow `if`/`return` at the `http` level, so the one-line include in each `server` block is required to get `444`.

> If nginx is behind a proxy/CDN, configure the `real_ip` module first. Otherwise `geo` sees the proxy's address, not the client's.

Run `nginx -t && nginx -s reload`.

### 3. Fail2ban action

Create `/etc/fail2ban/action.d/nginx-connector.conf`:

```ini
[Definition]
actionstart =
actionstop =
actioncheck =
actionban   = /opt/fail2ban-nginx-connector/fail2ban-nginx-connector.py ban <ip> <name>
actionunban = /opt/fail2ban-nginx-connector/fail2ban-nginx-connector.py unban <ip> <name>

[Init]
name = default
```

Use it in a jail (`/etc/fail2ban/jail.local`):

```ini
[nginx-badbots]
enabled = true
filter  = nginx-badbots
logpath = /var/log/nginx/access.log
action  = nginx-connector[name=%(__name__)s]
```

Restart Fail2ban: `systemctl restart fail2ban`.

### 4. Cron

`/etc/cron.d/fail2ban-nginx-connector`:

```
* * * * * root /opt/fail2ban-nginx-connector/fail2ban-nginx-connector.py reload
0 9 * * * root /opt/fail2ban-nginx-connector/fail2ban-nginx-connector.py stats-report
```

If there is no marker, `reload` exits immediately and does nothing.
The second line is optional: it sends the statistics for the last 24 hours to Telegram every day at 09:00.

## Usage

```
fail2ban-nginx-connector.py ban <ip> [name]     # add IP to the ban list, schedule reload
fail2ban-nginx-connector.py unban <ip> [name]   # remove IP from the ban list, schedule reload
fail2ban-nginx-connector.py reload              # reload nginx if a reload is scheduled
fail2ban-nginx-connector.py show                # print the current configuration
fail2ban-nginx-connector.py stats [--hours N]          # print statistics for the last N hours (default 24)
fail2ban-nginx-connector.py stats-report [--hours N]   # send the same statistics to Telegram
```

`name` is a label used in logs and Telegram messages, usually the jail name. It defaults to `unknown`.

`reload` exits with code `1` if `nginx -t` or `nginx -s reload` failed.

### Statistics

The statistics combine two sources and contain no IP addresses:

- **period** columns are counted from `LOG_FILE` (and `LOG_FILE.1`, if logrotate has rotated it) for the last N hours;
- **now** columns are the current state taken from `fail2ban-client status <jail>`.

```
                   -period-  ---now---
Jail                Ban Unb   Ban Fail
nginx-404            12   3    25    4
nginx-sqlinjection    4   0     9    0
nginx-form-spam       1   0     3    1
sshd                  0   0     0    7
--------------------------------------
Total                17   3    37   12

In BAN_FILE now:    36
Repeat bans:        2
Nginx reloads:      9
Errors:             0
```

- **period Ban / Unb**: IPs added to or removed from the ban list by each jail during the period.
- **now Ban**: IPs currently banned by the jail (fail2ban's `Currently banned`).
- **now Fail**: IPs that are collecting failures but are not banned yet (fail2ban's `Currently failed`).
- **In BAN_FILE now**: the number of IPs in `BAN_FILE`. It can be lower than the `now Ban` total, because an IP banned by two jails is one line in the file.
- **Repeat bans**: a jail tried to ban an IP that was already in the list.
- **Nginx reloads / Errors**: successful reloads and failed `nginx -t`/reloads.

Warnings are added below the numbers:

- `fail2ban-client is unavailable`: fail2ban is stopped, or the script isn't running as root. Only the log part is shown, with `-` in the **now** columns.
- `BAN_FILE has N IPs, but fail2ban has only M banned`: the file contains entries that fail2ban no longer tracks, for example after a manual edit. These IPs stay blocked until removed by hand with `unban`.

By default, all fail2ban jails are listed, including ones that don't use this connector (such as `sshd`). Set `STATS_JAILS` to show only your nginx jails.

## Configuration

The settings are read from `.env` next to the script. You can set another path with the
`FAIL2BAN_CONNECTOR_ENV` environment variable.

| Variable | Default | Description |
|---|---|---|
| `BAN_FILE` | **required** | nginx `geo` file with banned IPs |
| `LOG_FILE` | `fail2ban-connector.log` | Log file. Use an absolute path, because a relative one depends on the working directory of cron/Fail2ban. |
| `RELOAD_MARKER` | `/run/fail2ban-nginx-connector.reload` | Marker file meaning "reload needed" |
| `LOCK_FILE` | `/run/fail2ban-nginx-connector.lock` | Lock file for serializing parallel runs |
| `NGINX_BIN` | `/usr/sbin/nginx` | Full path to nginx. cron's `PATH` usually doesn't include `/usr/sbin`. |
| `NGINX_RELOAD_REPORT` | `0` | `1` sends a Telegram message on every successful reload |
| `ACTIONS_REPORT` | `1` | `1` sends a Telegram message on every ban/unban, including "already exists"/"not exists" warnings. Nginx errors are always sent. |
| `FAIL2BAN_CLIENT` | `/usr/bin/fail2ban-client` | Full path to `fail2ban-client`, used by `stats`/`stats-report` |
| `STATS_JAILS` | empty (all jails) | Comma-separated list of jails to show in statistics, e.g. `nginx-404,nginx-sqlinjection` |
| `SERVER_NAME` | empty | Server name shown in Telegram message titles |
| `TELEGRAM_TOKEN` | empty | Bot token from [@BotFather](https://t.me/BotFather) |
| `TELEGRAM_CHAT_ID` | empty | Chat/user ID to send messages to |

If `TELEGRAM_TOKEN` or `TELEGRAM_CHAT_ID` is empty, Telegram notifications are disabled.

## Troubleshooting

**`Reload skipped - nginx test failed` from cron, but `nginx -t` works in the console.**
The script can't find nginx in cron's limited `PATH`. Set `NGINX_BIN` to the output of `which nginx`.
The full error text from nginx is written to `LOG_FILE` and included in the Telegram message.

**The same error arrives every minute.**
This is expected. The marker is kept until nginx reloads successfully, so the error repeats on every cron run. Fix the nginx config and the next run will reload.
