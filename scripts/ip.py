import requests
import yaml
import re
import logging
import ipaddress
from typing import Set, Dict, List, Optional
import aiohttp
import asyncio
from functools import lru_cache
from prometheus_client import Counter, Histogram, start_http_server

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

CONFIG_FILE = 'config.yaml'

# Define IP ranges to exclude (private, loopback, link-local, multicast, broadcast)
EXCLUDE_RANGES = [
    "0.0.0.0/8",       # Current network
    "10.0.0.0/8",      # Private IPv4 range
    "100.64.0.0/10",   # Carrier-grade NAT
    "127.0.0.0/8",     # Loopback addresses
    "169.254.0.0/16",  # Link-local addresses
    "172.16.0.0/12",   # Private IPv4 range
    "192.0.0.0/24",    # IETF Protocol Assignments
    "192.0.2.0/24",    # Test-Net-1
    "192.88.99.0/24",  # 6to4 Relay Anycast
    "192.168.0.0/16",  # Private IPv4 range
    "198.18.0.0/15",   # Network Interconnect Device Benchmark Testing
    "198.51.100.0/24", # Test-Net-2
    "203.0.113.0/24", # Test-Net-3
    "224.0.0.0/4",     # Multicast addresses
    "240.0.0.0/4",     # Reserved for future use
    "255.255.255.255", # Limited broadcast
    "::/128",           # Unspecified address
    "::1/128",         # Loopback address
    "fc00::/7",        # Unique local addresses
    "fe80::/10",       # Link-local unicast addresses
]

EXCLUDE_NETWORKS = [ipaddress.ip_network(range_str) for range_str in EXCLUDE_RANGES]

# Add metrics
IP_PROCESSED = Counter('ips_processed_total', 'Number of IPs processed')
IP_PROCESSING_TIME = Histogram('ip_processing_seconds', 'Time spent processing IPs')

def load_config() -> Optional[Dict]:
    """Loads the configuration from config.yaml."""
    try:
        with open(CONFIG_FILE, 'r') as f:
            return yaml.safe_load(f)
    except FileNotFoundError:
        logging.error(f"Configuration file not found: {CONFIG_FILE}")
    except yaml.YAMLError as e:
        logging.error(f"Error parsing configuration file: {e}")
    return None

def fetch_content(url: str) -> Optional[str]:
    """Fetches the content from a given URL."""
    try:
        response = requests.get(url, timeout=10)
        response.raise_for_status()  # Raise HTTPError for bad responses (4xx or 5xx)
        return response.text
    except requests.exceptions.RequestException as e:
        logging.error(f"Error fetching content from {url}: {e}")
    return None

@lru_cache(maxsize=1024)
def is_excluded(ip_address: str) -> bool:
    """Checks if the given IP address or network is in the exclusion list."""
    try:
        ip = ipaddress.ip_network(ip_address, strict=False)  # Handle both IPs and networks
        return any(ip.overlaps(excluded_network) for excluded_network in EXCLUDE_NETWORKS)
    except ValueError:
        logging.warning(f"Invalid IP address or network: {ip_address}")
        return True  # Treat invalid IPs as excluded

def extract_ips(content: str) -> Set[str]:
    """Extracts IP addresses from the content and filters out excluded ranges."""
    ip_pattern = r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(?:/\d{1,2})?$'
    ips = set()
    for line in content.splitlines():
        line = line.strip()
        if line and not line.startswith('#'):  # Ignore empty lines and comments
            match = re.match(ip_pattern, line)
            if match:
                ip_or_network = match.group(0)
                if not is_excluded(ip_or_network):
                    ips.add(ip_or_network)
                else:
                    logging.debug(f"Excluding IP/Network: {ip_or_network}")
    return ips

@lru_cache(maxsize=1000)
async def resolve_ip(ip: str, dns_servers: List[str]) -> bool:
    """Cache DNS resolutions to improve performance"""
    # Implementation of DNS resolution logic
    pass

class IPValidator:
    """New class to handle IP validation logic"""
    def __init__(self, config: Dict):
        self.config = config
        self.cache = {}
        self.metrics_port = config.get('metrics_port', 9091)
        start_http_server(self.metrics_port)

    @IP_PROCESSING_TIME.time()
    async def validate_ip(self, ip: str) -> bool:
        if ip in self.cache:
            return self.cache[ip]
        
        result = await self._perform_validation(ip)
        self.cache[ip] = result
        IP_PROCESSED.inc()
        return result

    async def _perform_validation(self, ip: str) -> bool:
        # Implementation of IP validation logic
        pass

def main():
    """Main function to aggregate and save IP blacklists."""
    config = load_config()
    if not config or 'ip_lists' not in config or 'sources' not in config['ip_lists'] or 'output_file' not in config['ip_lists']:
        logging.error("Invalid IP list configuration in config.yaml.")
        return

    all_ips = set()
    ip_sources = config['ip_lists']['sources']
    output_file = config['ip_lists']['output_file']

    logging.info("Starting IP blacklist aggregation.")

    for source in ip_sources:
        name = source.get('name')
        url = source.get('url')
        format_type = source.get('format')  # Potentially use this later

        if not name or not url:
            logging.warning("Skipping IP source due to missing name or URL.")
            continue

        logging.info(f"Processing source: {name} from {url}")
        content = fetch_content(url)
        if content:
            ips = extract_ips(content)
            all_ips.update(ips)
            logging.info(f"Found {len(ips)} IPs from {name} (after exclusions).")

    # Save the aggregated IPs
    try:
        with open(output_file, 'w') as f:
            for ip in sorted(list(all_ips)):
                f.write(f"{ip}\n")
        logging.info(f"Successfully aggregated and saved {len(all_ips)} unique IPs to {output_file}")
    except IOError as e:
        logging.error(f"Error writing to output file {output_file}: {e}")

if __name__ == "__main__":
    main()