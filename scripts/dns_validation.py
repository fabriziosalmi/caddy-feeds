import asyncio
import concurrent.futures
import logging
import random
import re
import socket
import time
from typing import Dict, List, Optional, Set, Tuple

import aiodns
import requests
import yaml
import whois
from tenacity import (retry, retry_if_exception_type, stop_after_attempt,
                      wait_exponential)
from requests.exceptions import HTTPError, ConnectionError, Timeout
from urllib3.exceptions import NameResolutionError
import aiohttp
from aiohttp import ClientSession
from tqdm.asyncio import tqdm as tqdm_async

# Configure logging
logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s"
)

CONFIG_FILE = "config.yaml"
MAX_WORKERS = 100
PROGRESS_INTERVAL = 100
MAX_DNS_RETRIES = 2
HTTP_REQUEST_RETRIES = 2
HTTP_REQUEST_TIMEOUT = 3  # Increased timeout for potentially slow sources
FALLBACK_DNS_RETRIES = 2
WHOIS_TIMEOUT_MULTIPLIER = 1.5
AIOHTTP_TIMEOUT = 2  # Timeout for aiohttp requests

# More comprehensive list of public DNS servers
DEFAULT_DNS_SERVERS = [
    {"address": "8.8.8.8", "protocol": "plain", "description": "Google Public DNS"},
    {"address": "8.8.4.4", "protocol": "plain", "description": "Google Public DNS (Secondary)"},
    {"address": "1.1.1.1", "protocol": "plain", "description": "Cloudflare DNS"},
    {"address": "1.0.0.1", "protocol": "plain", "description": "Cloudflare DNS (Secondary)"},
    {"address": "9.9.9.9", "protocol": "plain", "description": "Quad9"},
    {"address": "149.112.112.112", "protocol": "plain", "description": "Quad9 (Secondary)"},
    {"address": "208.67.222.222", "protocol": "plain", "description": "OpenDNS Home"},
    {"address": "208.67.220.220", "protocol": "plain", "description": "OpenDNS Home (Secondary)"},
    {"address": "64.6.64.6", "protocol": "plain", "description": "Hurricane Electric DNS"},
    {"address": "64.6.65.6", "protocol": "plain", "description": "Hurricane Electric DNS (Secondary)"},
    {"address": "76.76.2.0", "protocol": "plain", "description": "Control D"},
    {"address": "76.76.10.0", "protocol": "plain", "description": "Control D (Secondary)"},
    {"address": "84.200.69.80", "protocol": "plain", "description": "DNS.WATCH"},
    {"address": "84.200.70.40", "protocol": "plain", "description": "DNS.WATCH (Secondary)"},
    {"address": "91.247.34.2", "protocol": "plain", "description": "Freifunk München"},
    {"address": "194.150.168.168", "protocol": "plain", "description": "Digitalcourage"},
    # Examples of DoH (DNS over HTTPS) - replace with actual working endpoints if needed
    {"address": "cloudflare-dns.com/dns-query", "protocol": "doh", "description": "Cloudflare DoH"},
    {"address": "dns.google/dns-query", "protocol": "doh", "description": "Google DoH"},
    {"address": "doh.quad9.net/dns-query", "protocol": "doh", "description": "Quad9 DoH"},
    # Examples of DoT (DNS over TLS) -  using IP addresses is generally preferred for initial connection
    {"address": "1.1.1.1", "protocol": "dot", "description": "Cloudflare DoT"}, # Same IP as plain, but uses TLS on port 853
    {"address": "9.9.9.9", "protocol": "dot", "description": "Quad9 DoT"},     # Same IP as plain, but uses TLS on port 853
]

# More comprehensive list of WHOIS servers
WHOIS_SERVERS = [
    "whois.iana.org",             # IANA WHOIS server, fallback
    "whois.verisign-grs.com",     # Verisign WHOIS server (for .com, .net)
    "whois.crsnic.net",           # Internic WHOIS server
    "whois.arin.net",             # ARIN WHOIS server (for IP addresses)
    "whois.ripe.net",             # RIPE NCC WHOIS server (Europe, Middle East, Central Asia)
    "whois.apnic.net",            # APNIC WHOIS server (Asia Pacific)
    "whois.lacnic.net",           # LACNIC WHOIS server (Latin America and Caribbean)
    "whois.afrinic.net",          # AfriNIC WHOIS server (Africa)
    "whois.nic.uk",              # Nominet WHOIS server (.uk)
    "whois.eu",                  # EURid WHOIS server (.eu)
    "whois.cira.ca",             # CIRA WHOIS server (.ca)
    "whois.denic.de",            # DENIC WHOIS server (.de)
    "whois.fr",                  # AFNIC WHOIS server (.fr)
    "whois.nic.ru",              # RU-CENTER WHOIS server (.ru)
    "whois.nic.br",              # NIC.br WHOIS server (.br)
    "whois.nic.es",              # NIC.ES WHOIS server (.es)
    "whois.registry.in",         # Registry.IN WHOIS server (.in)
    "whois.jprs.jp",             # JPRS WHOIS server (.jp)
    "whois.kr",                  # KISA/KRNIC WHOIS server (.kr)
    # Add more specific TLD WHOIS servers as needed, for example:
    "whois.ai",                  # Afilias (.ai)
    "whois.afilias-srs.net",      # Afilias (Generic)
    "whois.publicdomainregistry.com", # PublicDomainRegistry
]

# --- Helper Functions ---

@retry(
    stop=stop_after_attempt(HTTP_REQUEST_RETRIES),
    wait=wait_exponential(multiplier=1, min=2, max=10),
    retry=retry_if_exception_type((requests.exceptions.RequestException, Timeout)),
)
async def async_fetch_content(session: ClientSession, url: str, source_name: str) -> Optional[str]:
    """Asynchronously fetches the content from a given URL with retries."""
    try:
        async with session.get(url, timeout=HTTP_REQUEST_TIMEOUT) as response:
            response.raise_for_status()
            return await response.text()
    except HTTPError as e:
        if e.response.status_code == 404:
            logging.warning(f"Skipping source {source_name} from {url}: 404 Not Found")
            return None
        if e.response.status_code == 403:
            logging.warning(f"Skipping source {source_name} from {url}: 403 Forbidden")
            return None
        logging.error(f"Error fetching content from source {source_name} from {url}: {e}")
        raise  # Re-raise to trigger retry
    except (ConnectionError, NameResolutionError, Timeout) as e:
        logging.warning(f"Skipping source {source_name} from {url}: Network error {e}")
        return None
    except requests.exceptions.RequestException as e:
        logging.error(f"Error fetching content from source {source_name} from {url}: {e}")
        raise  # Re-raise to trigger retry

def load_config() -> Optional[Dict]:
    """Loads and validates the configuration from config.yaml."""
    try:
        with open(CONFIG_FILE, "r") as f:
            config = yaml.safe_load(f)
            if not config:
                raise ValueError("Configuration file is empty or invalid.")
            if 'dns_lists' not in config or not isinstance(config['dns_lists'], dict):
                raise ValueError("Invalid or missing 'dns_lists' section in config.yaml")
            if "sources" not in config["dns_lists"] or not config["dns_lists"]["sources"]:
                raise ValueError("No DNS sources defined in config.yaml")
            if "output_file" not in config["dns_lists"]:
                raise ValueError("No output file specified in config.yaml")
            if (
                "dns_servers" not in config["dns_lists"]
                or not config["dns_lists"]["dns_servers"]
            ):
                logging.warning(
                    "No DNS servers defined in config.yaml. Using default DNS servers."
                )
                config["dns_lists"]["dns_servers"] = DEFAULT_DNS_SERVERS
            config['dns_lists']['dns_query_timeout'] = float(config['dns_lists'].get('dns_query_timeout', 2.5))
            config['dns_lists']['whois_timeout'] = float(config['dns_lists'].get('whois_timeout', 5))
            return config
    except FileNotFoundError:
        logging.error(f"Configuration file not found: {CONFIG_FILE}")
        return None
    except yaml.YAMLError as e:
        logging.error(f"Error parsing configuration file: {e}")
        return None
    except ValueError as e:
        logging.error(f"Configuration error: {e}")
        return None

def extract_dns_entries(content: str, source_name: str) -> Set[str]:
    """Extracts DNS entries from the content."""
    dns_pattern = r"([a-zA-Z0-9-]+(?:[.][a-zA-Z0-9-]+)*[.][a-zA-Z]{2,})"
    dns_entries = set()
    if not content:
        logging.debug(f"Empty content received from source {source_name}. No DNS entries to process")
        return dns_entries
    for line in content.splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            matches = re.findall(dns_pattern, line)
            dns_entries.update(matches)
    if not dns_entries:
        logging.debug(f"No DNS entries were found using the current regex for source {source_name}.")
    return dns_entries

async def fallback_dns_resolution(fqdn: str, non_working_servers: Set[str]) -> bool:
    """Fallback DNS resolution using socket with retries."""
    for retry_count in range(FALLBACK_DNS_RETRIES):
        try:
            available_servers = [
                server["address"] for server in DEFAULT_DNS_SERVERS if server["address"] not in non_working_servers
            ]
            if not available_servers:
                logging.debug(f"No available DNS servers for fallback for {fqdn}")
                return False

            server_address = random.choice(available_servers)
            logging.debug(
                f"Trying fallback DNS resolution for {fqdn} using {server_address} at retry {retry_count}"
            )
            ip = socket.gethostbyname(fqdn)
            logging.debug(
                f"Fallback DNS resolution successful for {fqdn} to {ip} using {server_address}"
            )
            return True
        except socket.gaierror as e:
            logging.debug(
                f"Fallback DNS resolution failed for {fqdn}: {e} at retry {retry_count}"
            )
            await asyncio.sleep(0.1)  # small delay
    return False

def _whois_query(fqdn: str, server: str, whois_timeout: float) -> bool:
    """Helper function to perform a single WHOIS query."""
    try:
        logging.debug(f"Trying WHOIS lookup for {fqdn} using {server}")
        w = whois.query(fqdn, timeout=whois_timeout, server=server)
        return bool(w)  # Returns True if WHOIS information is found
    except whois.exceptions.WhoisCommandFailed as e:
        logging.debug(f"WHOIS command failed for {fqdn} using server {server}: {e}")
        return False
    except Exception as e:
        logging.debug(f"WHOIS lookup failed for {fqdn} using {server}: {e}")
        return False

def whois_lookup(fqdn: str, whois_servers: List[str], executor: concurrent.futures.ThreadPoolExecutor, whois_timeout: float) -> bool:
    """Performs a WHOIS lookup for a domain with multiple servers."""
    futures = [executor.submit(_whois_query, fqdn, server, whois_timeout) for server in whois_servers]
    for future in concurrent.futures.as_completed(futures):
        if future.result():
            return True
    return False

async def resolve_doh(session: ClientSession, fqdn: str, server: str, dns_query_timeout: float) -> Optional[List[str]]:
    """Resolves a domain using DNS over HTTPS."""
    try:
        url = f'https://{server}/dns-query?name={fqdn}&type=A'
        async with session.get(url, headers={'accept': 'application/dns-json'}, timeout=dns_query_timeout) as response:
            response.raise_for_status()
            data = await response.json()
            if "Answer" in data:
                return [record["data"] for record in data["Answer"] if record["type"] == 1]
            else:
                logging.debug(f"No 'Answer' section found in DoH response from {server} for {fqdn}")
                return None
    except (aiohttp.ClientError, asyncio.TimeoutError) as e:
        logging.debug(f"DoH resolution failed for {fqdn} using {server}: {e}")
        return None

async def resolve_dot(fqdn: str, server: str, dns_query_timeout: float) -> Optional[List[str]]:
    """Resolves a domain using DNS over TLS."""
    resolver = aiodns.DNSResolver(loop=asyncio.get_running_loop(), servers=[server], port=853)
    try:
        result = await asyncio.wait_for(resolver.query(fqdn, "A"), timeout=dns_query_timeout)
        return [record.host for record in result]
    except (aiodns.error.DNSError, asyncio.TimeoutError) as e:
        logging.debug(f"DoT resolution failed for {fqdn} using {server}: {e}")
        return None
    except Exception as e:
        logging.debug(f"Unexpected error during DoT resolution for {fqdn} using {server}: {e}")
        return None

async def check_dns_resolution(
    fqdn: str, dns_servers: List[Dict], max_retries: int, non_working_servers: Set[str], dns_query_timeout: float, session: ClientSession
) -> bool:
    """Asynchronously checks if a FQDN resolves to any IP address using aiodns with retries."""
    logging.debug(f"Checking DNS resolution for {fqdn}")

    for retry_count in range(max_retries):
        available_servers = [
            server for server in dns_servers if server["address"] not in non_working_servers
        ]
        if not available_servers:
            logging.debug(f"No available DNS servers to check {fqdn} at retry {retry_count}")
            return False

        server = random.choice(available_servers)
        address = server["address"]
        protocol = server["protocol"]
        try:
            logging.debug(f"Trying to resolve {fqdn} with server {address} using {protocol} at retry {retry_count}")

            if protocol == "doh":
                result = await resolve_doh(session, fqdn, address, dns_query_timeout)
            elif protocol == "dot":
                result = await resolve_dot(fqdn, address, dns_query_timeout)
            else:  # fallback to plain DNS
                resolver = aiodns.DNSResolver(
                    loop=asyncio.get_running_loop(), servers=[address]
                )
                result = await asyncio.wait_for(resolver.query(fqdn, "A"), timeout=dns_query_timeout)
                result = [record.host for record in result]

            if result:
                logging.debug(
                    f"Successfully resolved {fqdn} with server {address} using {protocol} at retry {retry_count} to {result}"
                )
                return True
            else:
                logging.debug(
                    f"Successfully queried {fqdn} with server {address} using {protocol} at retry {retry_count}, but no A records found."
                )
                continue

        except aiodns.error.DNSError as e:
            if e.args[0] == aiodns.error.ARES_ENOTFOUND:  # Non-existent domain
                logging.debug(f"Domain {fqdn} does not exist (NXDOMAIN).")
                return False
            logging.debug(
                f"Failed to resolve {fqdn} with server {address} using {protocol} at retry {retry_count}: {e}"
            )
            await asyncio.sleep(0.1 * (retry_count + 1))
            continue
        except asyncio.TimeoutError:
            logging.debug(
                f"Timeout resolving {fqdn} with server {address} using {protocol} at retry {retry_count}."
            )
            await asyncio.sleep(0.1 * (retry_count + 1))
            continue
        except aiohttp.ClientError as e:
            logging.debug(
                f"AIOHTTP error resolving {fqdn} with server {address} using {protocol} at retry {retry_count}: {e}"
            )
            await asyncio.sleep(0.1 * (retry_count + 1))
            continue

    # Fallback to socket resolution if aiodns fails
    logging.debug(f"Attempting fallback DNS resolution for {fqdn}")
    if await fallback_dns_resolution(fqdn, non_working_servers):
        return True

    if address and address not in non_working_servers:
        non_working_servers.add(address)
        logging.debug(
            f"DNS server {address} failed to resolve {fqdn} after all retries. Added to non-working servers"
        )
    return False

async def prune_dns_entries(
    dns_entries: Set[str],
    dns_servers: List[Dict],
    max_retries: int,
    whois_servers: List[str],
    executor: concurrent.futures.ThreadPoolExecutor,
    dns_query_timeout: float,
    whois_timeout: float,
    source_url: str
) -> Tuple[Set[str], int]:
    """Prunes the list of FQDNs by checking DNS resolution and WHOIS lookups in parallel."""
    pruned_entries = set()
    pruned_count = 0
    valid_count = 0
    total_entries = len(dns_entries)
    non_working_servers = set()
    progress = tqdm_async(dns_entries, desc=f"Pruning DNS entries from {source_url}", unit="domain")

    async with ClientSession(timeout=aiohttp.ClientTimeout(total=AIOHTTP_TIMEOUT)) as session:
        for fqdn in progress:
            is_valid = await check_dns_resolution(fqdn, dns_servers, max_retries, non_working_servers, dns_query_timeout, session)
            if is_valid:
                pruned_entries.add(fqdn)
                valid_count += 1
                progress.set_postfix({"status": "existing", "valid": valid_count, "pruned": pruned_count})
            else:
                if whois_lookup(fqdn, whois_servers, executor, whois_timeout * WHOIS_TIMEOUT_MULTIPLIER):
                    pruned_entries.add(fqdn)
                    valid_count += 1
                    logging.debug(f"WHOIS lookup successful for {fqdn}, adding to the list")
                    progress.set_postfix({"status": "whois", "valid": valid_count, "pruned": pruned_count})
                else:
                    pruned_count += 1
                    progress.set_postfix({"status": "non-existing", "valid": valid_count, "pruned": pruned_count})

    if non_working_servers:
        logging.info(f"Non-working DNS servers for {source_url}: {non_working_servers}")
    logging.info(
        f"Total entries for {source_url}: {total_entries}. Pruned {pruned_count} invalid DNS entries, Valid entries {valid_count}."
    )
    return pruned_entries, pruned_count

async def process_source(loop: asyncio.AbstractEventLoop, source: Dict, dns_servers: List[Dict], whois_servers: List[str], output_file: str, skipped_sources: Set[str], executor: concurrent.futures.ThreadPoolExecutor, dns_query_timeout: float, whois_timeout: float):
    """Processes a single DNS source."""
    name = source.get("name")
    url = source.get("url")
    if url in skipped_sources:
        logging.info(f"Skipping {name} from {url} as it previously returned no valid entries")
        return set()

    if not name or not url:
        logging.warning("Skipping DNS source due to missing name or URL.")
        return set()

    logging.info(f"Processing source: {name} from {url}")
    async with ClientSession() as session:
        content = await async_fetch_content(session, url, name)
        if content:
            dns_entries = extract_dns_entries(content, name)
            if not dns_entries:
                skipped_sources.add(url)
                return set()
            logging.info(f"Found {len(dns_entries)} DNS entries from {name}.")
            pruned_entries, _ = await prune_dns_entries(dns_entries, dns_servers, MAX_DNS_RETRIES, whois_servers, executor, dns_query_timeout, whois_timeout, url)
            return pruned_entries
        else:
            skipped_sources.add(url)
            return set()

async def main():
    """Main function to aggregate, prune, and save DNS blacklists."""
    loop = asyncio.get_event_loop()
    config = load_config()
    if not config or "dns_lists" not in config or "sources" not in config["dns_lists"] or "output_file" not in config["dns_lists"]:
        logging.error("Invalid DNS list configuration in config.yaml.")
        return

    all_dns_entries = set()
    dns_sources = config["dns_lists"]["sources"]
    output_file = config["dns_lists"]["output_file"]
    dns_servers = config["dns_lists"]["dns_servers"]
    dns_query_timeout = config['dns_lists']['dns_query_timeout']
    whois_timeout = config['dns_lists']['whois_timeout']
    random.shuffle(dns_servers)
    whois_servers = config.get("whois_servers", WHOIS_SERVERS)
    skipped_sources = set()

    logging.info("Starting DNS blacklist aggregation and pruning.")
    start_time = time.time()

    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        async def process_all_sources():
            tasks = [process_source(loop, source, dns_servers, whois_servers, output_file, skipped_sources, executor, dns_query_timeout, whois_timeout) for source in dns_sources]
            results = await tqdm_async.gather(*tasks, desc="Processing Sources")
            return set().union(*results)

        all_dns_entries = await process_all_sources()

    end_time = time.time()
    duration = end_time - start_time
    logging.info(f"DNS blacklist aggregation and pruning took: {duration:.2f} seconds")

    # Save the pruned DNS entries
    try:
        with open(output_file, "w") as f:
            for dns_entry in sorted(list(all_dns_entries)):
                f.write(f"{dns_entry}\n")
        logging.info(f"Successfully saved {len(all_dns_entries)} pruned DNS entries to {output_file}")
    except IOError as e:
        logging.error(f"Error writing to output file {output_file}: {e}")

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logging.info("Process interrupted by user. Exiting gracefully.")
    except Exception as e:
        logging.exception(f"Unexpected error: {e}")