# security-log-analyzer

Python CLI tool that analyzes authentication logs to detect suspicious login activity.

## Usage

Run the analyzer by providing a log file path and an optional threshold for failed
logins. IP addresses with failed attempts meeting or exceeding the threshold will be
reported.

```bash
python main.py /var/log/auth.log --threshold 5 --window-minutes 10 --mode rate \
  --spray-min-users 5 --spray-min-attempts 10
```

Use the default threshold of 5 when the `--threshold` flag is omitted.

### Time-window detection

By default, the analyzer runs in `rate` mode, which flags IPs that meet or exceed the
threshold for failed logins within a rolling time window (configured with
`--window-minutes`, default `5`). Use `--mode total` to disable the time-window logic
and evaluate counts across the entire log file instead.

### Password spraying detection

The analyzer also identifies password spraying behavior by tracking distinct
usernames per IP that trigger SSH "Failed password" lines. Use
`--spray-min-users` (default: 5) and `--spray-min-attempts` (default: 10) to tune
the minimum unique usernames and total failures required to report a suspect.
Matching IPs are printed under the **Password spraying suspects** section with
their attempt counts and username diversity.
