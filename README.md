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
python -m pip install --upgrade pip
python -m pip install .
```

### pipx

```bash
pipx install git+https://github.com/Wolfram178/vaptor.git
```

If you already have the repo cloned locally, this also works:

```bash
pipx install .
```

### Kali prerequisites

Install the external tooling separately on Kali:

```bash
sudo apt update
sudo apt install -y nmap python3-pipx
```

`testssl.sh` and Nessus are external tools and still need to be present on the Kali system or reachable over the network before SSL and Nessus stages can run.

For a one-shot setup, run:

```bash
bash scripts/kali_bootstrap.sh
```
