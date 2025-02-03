import yaml
import requests
import re  # new import
import logging  # new import

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] %(levelname)s: %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
)

# Updated helper function to filter private and reserved domains
def is_public_domain(domain: str) -> bool:
    private_suffixes = ('.local', '.lan', '.internal', '.private')
    reserved_domains = {
        'localhost',
        'broadcasthost',
        'ip6-allhosts',
        'ip6-allnodes',
        'ip6-allrouters',
    }
    if domain.lower() in reserved_domains:
        return False
    return not any(domain.lower().endswith(suffix) for suffix in private_suffixes)

# New helper function: validate FQDN format
def is_valid_fqdn(domain: str) -> bool:
    fqdn_regex = re.compile(
        r'^(?=.{4,253}$)(?:(?!-)[A-Za-z0-9-]{1,63}(?<!-)\.)+(?!-)[A-Za-z0-9-]{2,63}(?<!-)$'
    )
    return fqdn_regex.match(domain) is not None

def download_and_aggregate_dns_lists(config_file):
    """
    Downloads and aggregates DNS blacklist sources defined in a YAML config file.

    Args:
        config_file (str): Path to the YAML configuration file.
    """
    try:
        with open(config_file, 'r') as f:
            config = yaml.safe_load(f)
        if not isinstance(config, dict):
            logging.error("Invalid configuration format. Expected a dictionary.")
            return
    except FileNotFoundError:
        logging.error(f"Configuration file '{config_file}' not found.")
        return
    except yaml.YAMLError as e:
        logging.exception(f"Error parsing YAML configuration file '{config_file}': {e}")
        return

    dns_lists_config = config.get('dns_lists')
    if not dns_lists_config:
        logging.warning("No 'dns_lists' section found in config.yaml. No DNS blacklists will be processed.")
        return

    sources = dns_lists_config.get('sources', [])
    output_file = dns_lists_config.get('output_file', 'dns_blacklist.txt')

    aggregated_domains = set()  # Use a set to store unique domains

    if not sources:
        logging.warning("No DNS blacklist sources defined in config.yaml.")
        return

    logging.info("Downloading and processing DNS blacklist sources...")
    
    # Use a session for improved performance and custom headers
    with requests.Session() as session:
        session.headers.update({'User-Agent': 'Caddy-Feeds/1.0'})
        for source in sources:
            source_name = source.get('name', 'Unnamed Source')
            source_url = source.get('url')

            if not source_url:
                logging.warning(f"No URL provided for source '{source_name}'. Skipping.")
                continue

            try:
                logging.info(f"Downloading '{source_name}' from: {source_url}")
                response = session.get(source_url, stream=True, timeout=10)
                response.raise_for_status()  # Raise HTTPError for bad responses (4xx or 5xx)

                for line in response.iter_lines(decode_unicode=True):
                    if line:  # Skip empty lines
                        try:
                            line = line.strip()
                            if line.startswith(('0.0.0.0', '#', '::1', '127.0.0.1')):
                                # Skip lines that are likely comments or localhost entries in hosts files
                                continue
                            parts = line.split()
                            # Assuming typical hosts file format: IP domain1 domain2 ... or just domain per line
                            if len(parts) > 1:
                                # Take the domain part (often after IP in hosts files)
                                domain = parts[1] # Assuming domain is the second element after IP
                                aggregated_domains.add(domain)
                            elif len(parts) == 1 and "." in parts[0]: # Handle cases where only domain is listed
                                aggregated_domains.add(parts[0])
                        except Exception as line_e:
                            logging.error(f"Error processing a line from '{source_name}': {line_e}")

            except requests.exceptions.RequestException as e:
                logging.exception(f"Error downloading '{source_name}' from {source_url}: {e}")
            except Exception as e:
                logging.exception(f"An unexpected error occurred while processing '{source_name}': {e}")

    logging.info("Finished downloading and processing DNS blacklist sources.")
    logging.info(f"Writing aggregated DNS blacklist to: {output_file}")

    # Remove private FQDNs and non valid FQDNs from the final aggregated blacklist
    aggregated_domains = {domain for domain in aggregated_domains if is_public_domain(domain) and is_valid_fqdn(domain)}

    try:
        with open(output_file, 'w') as outfile:
            for domain in sorted(aggregated_domains): # Sort domains alphabetically for better readability
                outfile.write(domain + '\n')
        logging.info(f"Successfully wrote {len(aggregated_domains)} unique public domains to '{output_file}'.")
    except IOError as e:
        logging.error(f"Error writing to output file '{output_file}': {e}")


if __name__ == "__main__":
    config_file = "config.yaml"  # Assuming your config.yaml is in the same directory
    download_and_aggregate_dns_lists(config_file)