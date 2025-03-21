#!/usr/bin/python3
import argparse
from bs4 import BeautifulSoup
import requests
import sys
import re
import time
import asyncio
from pyppeteer import launch

requests.packages.urllib3.disable_warnings()

async def search_asn_with_browser(asn, browser_path='/usr/bin/./chromium-browser-stable'):
    """Replaces the original search_asn function using Pyppeteer instead of Selenium
    but maintains identical functionality and results"""
    bgphe_url = "https://bgp.he.net/"
    uri = asn
    
    browser_args = [
        '--no-sandbox',
        '--no-zygote',
        '--disable-features=IsolateOrigins,site-per-process,SitePerProcess',
        '--disable-site-isolation-trials',
        '--disable-setuid-sandbox',
        '--disable-dev-shm-usage',
        '--disable-notifications',
        '--window-size=1024,768',
        '--start-maximized',
        '--ignore-certificate-errors',
        '--disable-blink-features=AutomationControlled',
        '--disable-audio-output',
        '--disable-session-crashed-bubble',
        '--disable-accelerated-2d-canvas',
        '--no-first-run',
        '--noerrdialogs',
        '--disable-gpu',
    ]
    
    browser = await launch({
        'headless': True,
        'ignoreHTTPSErrors': True,
        'executablePath': browser_path,
        'ignoreDefaultArgs': [
            "--no-startup-window",
            "--disable-crash-reporter",
            "--disable-crashpad-for-testing",
            "--disable-gpu-watchdog",
        ],
        'args': browser_args
    })
    
    page = await browser.newPage()
    
    # Set user agent to avoid detection
    await page.setUserAgent('Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36')
    
    # Navigate to BGP.HE
    try:
        await page.goto(bgphe_url + uri, {'timeout': 30000})
        
        # Wait for the table to appear - consistent with original 10 second timeout
        await page.waitForSelector('#table_prefixes4', {'timeout': 10000})
    except Exception as e:
        print(f"[!] Timeout waiting for BGP.HE to load data for {asn}")
        await browser.close()
        return []
    
    # Get the page content - exactly how the original does
    try:
        content = await page.content()
    finally:
        await browser.close()
    
    # Parse the HTML with the same parser as original
    soup = BeautifulSoup(content, 'html.parser')
    
    tables = soup.find_all(id='table_prefixes4')
    ranges = []
    if len(tables) > 0:
        table = tables[0]
        links = table.find_all("a", href=True)
        
        filtered_links = [link["href"] for link in links if link["href"].startswith("/net/")]

        for link in filtered_links:
            ranges.append(link.replace("/net/", ""))
    
    return ranges

def validate_cidr(cidr):
    cidr_regex = "\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(?:/\d{1,2}|)"
    m = re.search(cidr_regex, cidr)
    if not m:
        fail("Invalid CIDR: " + cidr)

def validate_asn(asn):
    asn_regex = "^AS\d+$"
    m = re.search(asn_regex, asn)
    if not m:
        fail("Invalid ASN: " + asn)

def search_cidr(cidr):
    robtex_url = "https://www.robtex.com/cidr/"
    uri = cidr.replace("/", "-")
    
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/132.0.6834.210 Safari/537.36'
    }

    session = requests.Session()
    try:
        response = session.get(str(robtex_url) + uri, verify=False, headers=headers, timeout=10)
        if (response.status_code != 200):
            fail("Robtex invalid HTTP response: " + str(response.status_code))
    except requests.exceptions.RequestException as e:
        fail(f"Request to Robtex failed: {str(e)}")
    
    soup = BeautifulSoup(response.text, 'html.parser')
    
    links = soup.find_all("a", href=True)
    filtered_ip_links = [link["href"] for link in links if link["href"].startswith("https://www.robtex.com/ip-lookup/")]
    filtered_named_links = [link["href"] for link in links if link["href"].startswith("https://www.robtex.com/dns-lookup/")]

    hostnames = {}
    index = 0
    for link in filtered_named_links:
        if index >= len(filtered_ip_links):
            break  # Prevent index out of range errors
            
        h = link.replace("https://www.robtex.com/dns-lookup/", "")
        ip = filtered_ip_links[index].replace("https://www.robtex.com/ip-lookup/", "")
        
        actual_findings = hostnames.get(h)
        if actual_findings is not None:
            actual_findings.update([ip])
        else:
            actual_findings = set([ip])
        hostnames.update({h: actual_findings})
        
        index = index + 1
    
    return hostnames

def fail(msg):
    print("[-] Error: " + msg)
    sys.exit(1)

async def process_asn(asns, browser_path):
    final_findings = {}
    for asn in asns:
        validate_asn(asn)
        ranges = await search_asn_with_browser(asn, browser_path)
        for r in ranges:
            fresh_findings = search_cidr(r)
            for fresh_finding_fqdn in fresh_findings.keys():
                actual_findings_ips = final_findings.get(fresh_finding_fqdn)
                if actual_findings_ips is None:
                    actual_findings_ips = fresh_findings.get(fresh_finding_fqdn)
                else:
                    actual_findings_ips.update(fresh_findings.get(fresh_finding_fqdn))
                final_findings.update({fresh_finding_fqdn: actual_findings_ips})

            time.sleep(1)
    return final_findings

def main():
    parser = argparse.ArgumentParser(description='Find hostnames from ASN or CIDR - Robtex x BGP.HE')
    parser.add_argument('-c', type=str, required=False, dest='cidr', help="CIDR(s) (Single or multiple separated by commas - Ex: 192.168.0.0/24 or 192.168.0.0/24,192.168.1.0/24)")
    parser.add_argument('-a', type=str, required=False, dest='asn', help="ASN(s) (Single or multiple separated by commas - Ex: AS1234 or AS1234,AS4561)")
    parser.add_argument('--hosts', action="store_true", default=False, dest='hosts', help="Generate /etc/hosts like file")
    parser.add_argument('--fqdn', action="store_true", default=False, dest='fqdn', help="Only display found FQDN")
    parser.add_argument('--filter', type=str, required=False, dest='filter', help="Filter FQDN against regex (Ex: ^.*example\.org$)")
    parser.add_argument('--browser', type=str, required=False, dest='browser', default='/usr/bin/./chromium-browser-stable', help="Path to browser executable")
    args = parser.parse_args()

    # Validate the filter before launching any search activities
    filter = ""
    if args.filter:
        try:
            filter = re.compile(args.filter)
        except re.error:
            fail("Invalid filter: not a regex filter")
    
    # By default : for each value of the list, the key is FQDN and values are IPs
    final_findings = {}
    if (args.cidr):
        cidrs = args.cidr.split(",")
        for cidr in cidrs:
            validate_cidr(cidr)
            final_findings.update(search_cidr(cidr))
    elif (args.asn):
        asns = args.asn.split(",")
        final_findings = asyncio.get_event_loop().run_until_complete(process_asn(asns, args.browser))
    else:
        fail("Invalid given parameters. Should select -c or -a.")
    
    # Filter before display
    if filter:
        filtered_final_findings = {key: value for key, value in final_findings.items() if re.match(args.filter, key)}
        final_findings = filtered_final_findings

    # Reverse dictionnary to display as hosts file
    if args.hosts:
        result = {}
        index = 0

        for ips in final_findings.values():
            for i in ips:
                fqdn_list = list(final_findings)[index]
                current_fqdn_list = result.get(i)
                if current_fqdn_list is None:
                    current_fqdn_list = set([fqdn_list])
                else:
                    current_fqdn_list.update([fqdn_list])
                result.update({i: current_fqdn_list})
            index = index + 1
        # Display as /etc/hosts file
        for item in result.keys():
            print(item + " " + " ".join(result.get(item)))
    else:
        if args.fqdn:
            for h in final_findings.keys():
                print(h)
        else:
            for h in final_findings.keys():
                print(h + ":" + " ".join(final_findings.get(h)))

if __name__ == '__main__':
    main()
