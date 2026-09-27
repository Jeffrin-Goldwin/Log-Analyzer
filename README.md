# Log-Analyzer

A small Bash script that parses **nginx access logs** (combined format) and
prints a quick summary — request counts, top IPs, top paths, 404s, and a
per-hour histogram. I built this as a project to learn Bash.

## What it does

Given a log file, `loganalyzer.sh` reports:

- Total number of log lines
- Number of unique IP addresses
- Count of `2xx` and `4xx` responses
- Top N IPs
- Top N requested paths
- Top N paths that returned `404`
- Requests per hour, drawn as a simple `#` bar chart

You can also filter to a single status class (`2xx`, `3xx`, `4xx`, `5xx`).

## Requirements

- Bash
- Standard Unix tools: `awk`, `sort`, `uniq`, `wc`, `head`, `mktemp`

(These come by default on Linux/macOS. On Windows, run it under Git Bash or WSL.)

## Usage

```bash
./src/loganalyzer.sh [-n N] [-s CLASS] [-h] <logfile>
```

Options:

| Flag       | Description                                          |
|------------|------------------------------------------------------|
| `-n N`     | Show top N rows (default: 10)                        |
| `-s CLASS` | Only analyse requests with this status class (`2xx`, `3xx`, `4xx`, `5xx`) |
| `-h`       | Show help                                            |

The report is colorized when run in a terminal. Colors are turned off
automatically when the output is piped to a file, or you can disable them
explicitly with `NO_COLOR=1`.

### Examples

```bash
# Analyse a log file with defaults (top 10)
./src/loganalyzer.sh src/access.log

# Show the top 5 rows
./src/loganalyzer.sh -n 5 src/access.log

# Only look at 5xx (server error) requests
./src/loganalyzer.sh -s 5xx src/access.log
```

## Generating sample logs

The repo includes a Python helper that generates realistic fake nginx logs to
test against. It plants heavy-hitter IPs, scanner probes, a request burst, and a
`5xx` incident window so there's always something interesting to find.

```bash
# 5000 lines to stdout
python3 scripts/gen_access_logs.py

# 20000 lines written to a file
python3 scripts/gen_access_logs.py -n 20000 -o src/access.log

# Reproducible output
python3 scripts/gen_access_logs.py --seed 42 -o src/access.log
```

Run `python3 scripts/gen_access_logs.py -h` for all options.

> **Note:** Log files (`*.log`, `*.log.gz`) are git-ignored so they don't get
> pushed to GitHub. Generate your own with the script above.

## Project layout

```
.
├── src/
│   └── loganalyzer.sh      # the main analyzer script
└── scripts/
    └── gen_access_logs.py  # generates sample nginx logs for testing
```
