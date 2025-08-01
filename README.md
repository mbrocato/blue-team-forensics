# Blue Team Forensic Toolkit

This repository contains Python scripts for entry-level forensics: parsing Windows event logs for anomalies and analyzing memory dumps with Volatility.

## Setup
1. Install dependencies: `pip install -r requirements.txt`. Install Volatility3 separately: `pip install volatility3`.
2. Run the script: `python main.py --help` for options.

## Features
- Parse event logs for login anomalies.
- Analyze memory dumps for processes and networks.
- Generate Markdown reports.

Example: `python main.py --log path/to/event_log.xml --memory path/to/memory.dmp --report`

## License
MIT
