# security-log-analyzer

Python CLI tool that analyzes authentication logs to detect suspicious login activity.

## Usage

Run the analyzer by providing a log file path and an optional threshold for failed
logins. IP addresses with failed attempts meeting or exceeding the threshold will be
reported.

```bash
python main.py /var/log/auth.log --threshold 5
```

Use the default threshold of 5 when the `--threshold` flag is omitted.
