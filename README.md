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

### One-command local install

Clone the repo and install Vaptor from the repository root:

```bash
git clone https://github.com/Wolfram178/vaptor.git
cd vaptor
python scripts/install.py
```

After that, you can run Vaptor from anywhere in the same environment:

```bash
vaptor -i targets.txt
```

### Manual install

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

PoC screenshots are generated from the captured scan output using a GUI window snapshot. The Python dependency `mss` is installed automatically, but you still need a graphical session available on Linux for the screenshot step to work. If no GUI is available, Vaptor falls back to the text-rendered PoC image.

For a one-shot setup, run:

```bash
bash scripts/kali_bootstrap.sh
```
