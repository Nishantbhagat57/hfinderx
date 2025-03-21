# hfinderx
ASN and CIDR Hostname Finder - A tool to discover hostnames associated with Autonomous System Numbers (ASNs) or CIDR blocks by scraping BGP.HE and Robtex.

## Overview

This tool helps security researchers and network administrators to:

- Find all hostnames associated with specific ASNs
- Discover hostnames for CIDR blocks

It uses a headless Chromium browser (via Pyppeteer) to gather IP ranges from BGP.HE and then queries Robtex to find associated hostnames.

This is just a rewrite of https://github.com/cosad3s/hfinder in Pyppeteer.

## Features

- **ASN Lookup**: Discover all CIDRs associated with an ASN
- **CIDR Lookup**: Find all hostnames for specific CIDR blocks
- **Multiple Inputs**: Process multiple ASNs or CIDRs in a single run
- **Filtering**: Filter results using regex patterns
- **Output Formats**: Display as FQDN only or hosts file format

## Requirements

- Python 3.6+
- Chromium browser installed (default path: `/usr/bin/chromium-browser-stable`)

## Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/Nishantbhagat57/hfinderx.git
   cd hfinderx
   ```

2. Install required packages:
   ```bash
   pip3 install -r requirements.txt
   ```

3. Ensure you have Chromium installed:
   ```bash
   # For Debian/Ubuntu
   apt-get install chromium-browser
   
   # For Arch Linux
   pacman -S chromium
   
   # For CentOS/RHEL
   yum install chromium
   ```

## Usage

### Basic Usage

```bash
# Find hostnames for an ASN
python3 hfinderx.py -a "AS15169"

# Find hostnames for a CIDR block
python3 hfinderx.py -c "192.168.1.0/24"

# Find hostnames for multiple ASNs
python3 hfinderx.py -a "AS15169,AS16509"

# Find hostnames for multiple CIDRs
python3 hfinderx.py -c "192.168.1.0/24,10.0.0.0/8"
```

### Advanced Options

```bash
# Generate hosts file format
python3 hfinderx.py -a "AS15169" --hosts

# Show only FQDNs
python3 hfinderx.py -a "AS15169" --fqdn

# Filter results with regex
python3 hfinderx.py -a "AS15169" --filter "^.*example\.com$"

# Use a different Chromium path
python3 hfinderx.py -a "AS15169" --browser /usr/bin/chromium
```

### Full Command Reference

```
usage: hfinderx.py [-h] [-c CIDR] [-a ASN] [--hosts] [--fqdn] [--filter FILTER] [--browser BROWSER]

Find hostnames from ASN or CIDR - Robtex x BGP.HE

optional arguments:
  -h, --help       show this help message and exit
  -c CIDR          CIDR(s) (Single or multiple separated by commas - Ex: 192.168.0.0/24 or 192.168.0.0/24,192.168.1.0/24)
  -a ASN           ASN(s) (Single or multiple separated by commas - Ex: AS1234 or AS1234,AS4561)
  --hosts          Generate /etc/hosts like file
  --fqdn           Only display found FQDN
  --filter FILTER  Filter FQDN against regex (Ex: ^.*example\.org$)
  --browser BROWSER  Path to browser executable (default: /usr/bin/chromium-browser-stable)
```

## How It Works

1. **ASN Lookup**:
   - Connects to BGP.HE using Pyppeteer with a headless Chromium browser
   - Extracts all IP ranges (CIDRs) associated with the ASN
   - Processes each CIDR block

2. **CIDR Processing**:
   - Connects to Robtex's CIDR lookup page
   - Extracts all hostname-to-IP mappings
   - Aggregates results

3. **Output Processing**:
   - Filters results based on specified regex (if provided)
   - Formats output as requested (normal, hosts format, or FQDN-only)

## Examples

### Finding Google Cloud hostnames

```bash
python3 hfinderx.py -a "AS15169" --filter ".*\.googleusercontent\.com$" --fqdn
```

### Creating a hosts file for Amazon AWS IP ranges

```bash
python3 hfinderx.py -a "AS16509" --hosts > aws-hosts.txt
```

## Notes and Limitations

- Rate limiting: The tool includes a 1-second delay between requests to avoid being blocked
- The tool depends on the structure of BGP.HE and Robtex websites, which may change over time
- Large ASNs may take significant time to process
- Results are only as accurate as the data provided by BGP.HE and Robtex

## Troubleshooting

- If you encounter browser launch issues, verify your Chromium installation and path
- Use a custom browser path if needed: `--browser /path/to/chromium`
- If you get timeouts, try again later as the target websites may be rate-limiting requests

## Disclaimer

Use this tool responsibly and ethically. Do not use it for unauthorized access to systems or networks.
