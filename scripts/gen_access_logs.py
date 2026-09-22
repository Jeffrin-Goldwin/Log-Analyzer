#!/usr/bin/env python3
"""
Generate fake nginx access logs in "combined" format.

    $remote_addr - $remote_user [$time_local] "$request" $status $body_bytes_sent "$http_referer" "$http_user_agent"

Built-in patterns so every milestone has something to find:
  - A few "heavy" IPs dominate traffic (M2 top-N looks realistic)
  - Traffic follows a day/night curve (M3 hourly bar chart has shape)
  - Scanner IPs probe .env / .sql / backup paths (M5 path detector)
  - A burst IP fires 100+ requests in one minute (M5 rate detector)
  - A 5xx incident window (M6 red output has something to color)

Usage:
    python3 gen_access_log.py                              # 5000 lines to stdout
    python3 gen_access_log.py -n 20000 -o access.log
    python3 gen_access_log.py --start "2026-06-18 00:00" --hours 48 -o access.log
    python3 gen_access_log.py -n 50000 --gzip -o old.log.gz
    python3 gen_access_log.py --seed 42                    # reproducible output
"""

import argparse
import gzip
import random
import sys
from datetime import datetime, timedelta, timezone

IST = timezone(timedelta(hours=5, minutes=30))

NORMAL_PATHS = [
    "/", "/index.html", "/about", "/contact", "/blog", "/blog/bash-tips",
    "/blog/awk-intro", "/products", "/products/42", "/products/117",
    "/cart", "/checkout", "/login", "/logout", "/search?q=shoes",
    "/api/v1/users", "/api/v1/orders", "/api/v1/health",
    "/static/css/main.css", "/static/js/app.js", "/static/img/logo.png",
    "/favicon.ico", "/robots.txt",
]

# Paths that don't exist -> mostly 404s
BROKEN_PATHS = [
    "/old-page", "/blog/deleted-post", "/products/9999", "/wp-login.php",
    "/images/missing.jpg", "/docs/v1", "/promo2025",
]

# What a scanner enumerates (M5)
SCANNER_PATHS = [
    "/.env", "/.env.bak", "/.git/config", "/backup.sql", "/db.sql",
    "/dump.sql", "/backup.zip", "/backup/", "/config.php.bak",
    "/admin/.env", "/phpmyadmin/", "/.aws/credentials", "/wp-config.php.bak",
]

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:129.0) Gecko/20100101 Firefox/129.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 Mobile/15E148",
    "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 Chrome/128.0 Mobile Safari/537.36",
    "curl/8.5.0",
    "Googlebot/2.1 (+http://www.google.com/bot.html)",
]
SCANNER_AGENTS = ["python-requests/2.31.0", "Go-http-client/1.1", "zgrab/0.x", "Mozilla/5.0 (compatible; Nmap)"]

REFERERS = ["-", "-", "-", "https://www.google.com/", "https://duckduckgo.com/", "https://example.com/blog"]

# Relative traffic weight per hour of day (quiet at night, peak evening)
HOUR_WEIGHTS = [2, 1, 1, 1, 1, 2, 4, 6, 8, 9, 9, 10, 10, 9, 9, 9, 10, 11, 12, 12, 10, 8, 5, 3]


def rand_ip(rng):
    return f"{rng.randint(1, 223)}.{rng.randint(0, 255)}.{rng.randint(0, 255)}.{rng.randint(1, 254)}"


def fmt_time(dt):
    # 18/Jun/2026:05:02:38 +0530  (month name fixed to English, not locale)
    months = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"]
    return f"{dt.day:02d}/{months[dt.month - 1]}/{dt.year}:{dt:%H:%M:%S} {dt:%z}"


def fmt_line(ip, dt, method, path, status, size, referer, agent):
    return f'{ip} - - [{fmt_time(dt)}] "{method} {path} HTTP/1.1" {status} {size} "{referer}" "{agent}"'


def weighted_time(rng, start, hours):
    """Pick a timestamp in [start, start+hours) biased by HOUR_WEIGHTS."""
    buckets = list(range(hours))
    weights = [HOUR_WEIGHTS[(start + timedelta(hours=h)).hour] for h in buckets]
    h = rng.choices(buckets, weights=weights)[0]
    return start + timedelta(hours=h, seconds=rng.randint(0, 3599))


def normal_request(rng, dt, ip, incident):
    roll = rng.random()
    if roll < 0.08:
        path, status = rng.choice(BROKEN_PATHS), 404
    else:
        path = rng.choice(NORMAL_PATHS)
        status = rng.choices([200, 304, 301, 403, 500, 502, 503],
                             weights=[85, 6, 3, 1, 2, 1, 1])[0]
    if incident and path.startswith("/api") and rng.random() < 0.6:
        status = rng.choice([500, 502, 503, 504])

    method = "POST" if path in ("/login", "/checkout", "/api/v1/orders") and rng.random() < 0.5 else "GET"
    size = 0 if status in (304, 301) else rng.randint(150, 60000)
    return fmt_line(ip, dt, method, path, status, size, rng.choice(REFERERS), rng.choice(USER_AGENTS))


def generate(n, start, hours, rng):
    entries = []  # (datetime, line)
    end = start + timedelta(hours=hours)

    # Pool of client IPs; a handful are "heavy hitters"
    pool = [rand_ip(rng) for _ in range(max(50, n // 25))]
    heavy = pool[:8]
    ip_weights = [40 if ip in heavy else 1 for ip in pool]

    # 5xx incident: a 20-minute window somewhere in the middle
    inc_start = start + timedelta(hours=hours // 2, minutes=rng.randint(0, 40))
    inc_end = inc_start + timedelta(minutes=20)

    # Reserve ~10% of lines for suspicious activity
    n_normal = int(n * 0.9)
    for _ in range(n_normal):
        dt = weighted_time(rng, start, hours)
        ip = rng.choices(pool, weights=ip_weights)[0]
        entries.append((dt, normal_request(rng, dt, ip, inc_start <= dt < inc_end)))

    remaining = n - n_normal

    # Scanners: 3 IPs, each walks the sensitive path list in a few seconds
    scanners = [rand_ip(rng) for _ in range(3)]
    for ip in scanners:
        t = start + timedelta(seconds=rng.randint(0, hours * 3600 - 120))
        agent = rng.choice(SCANNER_AGENTS)
        for path in SCANNER_PATHS:
            t += timedelta(milliseconds=rng.randint(100, 900))
            status = rng.choices([404, 403, 200], weights=[80, 15, 5])[0]
            entries.append((t, fmt_line(ip, t, "GET", path, status, rng.randint(100, 600), "-", agent)))
            remaining -= 1

    # Burst IP: hammers /login inside a single minute (rate detector target)
    burst_ip = rand_ip(rng)
    burst_minute = start + timedelta(minutes=rng.randint(0, hours * 60 - 1))
    burst_minute = burst_minute.replace(second=0)
    for _ in range(max(remaining, 120)):
        t = burst_minute + timedelta(seconds=rng.randint(0, 59))
        status = rng.choices([401, 200, 429], weights=[80, 5, 15])[0]
        entries.append((t, fmt_line(burst_ip, t, "POST", "/login", status, rng.randint(80, 300), "-", "python-requests/2.31.0")))

    entries = [e for e in entries if e[0] < end]
    entries.sort(key=lambda e: e[0])
    return [line for _, line in entries], scanners, burst_ip, burst_minute, (inc_start, inc_end)


def main():
    p = argparse.ArgumentParser(description="Generate fake nginx combined-format access logs.")
    p.add_argument("-n", "--lines", type=int, default=5000, help="approximate number of lines (default 5000)")
    p.add_argument("--start", default="2026-06-18 00:00", help='start time, "YYYY-MM-DD HH:MM" (IST)')
    p.add_argument("--hours", type=int, default=24, help="span of the log in hours (default 24)")
    p.add_argument("-o", "--output", help="output file (default: stdout)")
    p.add_argument("--gzip", action="store_true", help="gzip the output file")
    p.add_argument("--seed", type=int, help="random seed for reproducible logs")
    args = p.parse_args()

    if args.hours < 1:
        p.error("--hours must be >= 1")

    rng = random.Random(args.seed)
    start = datetime.strptime(args.start, "%Y-%m-%d %H:%M").replace(tzinfo=IST)
    lines, scanners, burst_ip, burst_min, incident = generate(args.lines, start, args.hours, rng)
    data = "\n".join(lines) + "\n"

    if args.output:
        opener = gzip.open if args.gzip else open
        with opener(args.output, "wt") as f:
            f.write(data)
    else:
        sys.stdout.write(data)

    # Answer key goes to stderr so it never pollutes the log itself
    print(f"# {len(lines)} lines", file=sys.stderr)
    print(f"# scanner IPs: {', '.join(scanners)}", file=sys.stderr)
    print(f"# burst IP: {burst_ip} at {burst_min:%d/%b/%Y:%H:%M}", file=sys.stderr)
    print(f"# 5xx incident: {incident[0]:%H:%M} - {incident[1]:%H:%M}", file=sys.stderr)


if __name__ == "__main__":
    main()
