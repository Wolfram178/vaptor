# Vaptor

Vaptor is an automated VAPT pipeline tool that integrates Nmap, testssl, and Nessus to perform vulnerability scanning, correlation, and reporting.

## Features

- Automated Nmap + testssl + Nessus scanning
- Parallel execution
- Smart scanning (port-based decisions)
- Vulnerability correlation engine
- Multi-sheet Excel reporting
- JSON output support
- PoC screenshot generation

## Installation

```bash
git clone https://github.com/Wolfram178/vaptor.git
cd vaptor
pip install -e .