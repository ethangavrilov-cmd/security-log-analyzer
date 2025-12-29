# security-log-analyzer

Python CLI tool that analyzes authentication logs to detect suspicious login activity.

## Usage

Run the analyzer by providing a log file path and an optional threshold for failed
logins. IP addresses with failed attempts meeting or exceeding the threshold will be
reported.

```bash
python main.py /var/log/auth.log --threshold 5 --window-minutes 10 --mode rate
```

Use the default threshold of 5 when the `--threshold` flag is omitted.

### Time-window detection

By default, the analyzer runs in `rate` mode, which flags IPs that meet or exceed the
threshold for failed logins within a rolling time window (configured with
`--window-minutes`, default `5`). Use `--mode total` to disable the time-window logic
and evaluate counts across the entire log file instead.
