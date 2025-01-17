import requests
import yaml
import re
import logging

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

CONFIG_FILE = 'config.yaml'

def load_config():
    """Loads the configuration from config.yaml."""
    try:
        with open(CONFIG_FILE, 'r') as f:
            return yaml.safe_load(f)
    except FileNotFoundError:
        logging.error(f"Configuration file not found: {CONFIG_FILE}")
        return None
    except yaml.YAMLError as e:
        logging.error(f"Error parsing configuration file: {e}")
        return None

def fetch_content(url):
    """Fetches the content from a given URL."""
    try:
        response = requests.get(url, timeout=10)
        response.raise_for_status()  # Raise HTTPError for bad responses (4xx or 5xx)
        return response.text
    except requests.exceptions.RequestException as e:
        logging.error(f"Error fetching content from {url}: {e}")
        return None

def extract_dns_entries(content):
    """Extracts DNS entries from the content."""
    # This regex is a basic example and might need adjustments based on the format of your DNS lists.
    # It matches valid hostname patterns.
    dns_pattern = r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.){1,}(?:[a-zA-Z]{2,})$'
    dns_entries = set()
    for line in content.splitlines():
        line = line.strip()
        if line and not line.startswith('#'):  # Ignore empty lines and comments
            match = re.match(dns_pattern, line)
            if match:
                dns_entries.add(line)
    return dns_entries

def main():
    """Main function to aggregate and save DNS blacklists."""
    config = load_config()
    if not config or 'dns_lists' not in config or 'sources' not in config['dns_lists'] or 'output_file' not in config['dns_lists']:
        logging.error("Invalid DNS list configuration in config.yaml.")
        return

    all_dns_entries = set()
    dns_sources = config['dns_lists']['sources']
    output_file = config['dns_lists']['output_file']

    logging.info("Starting DNS blacklist aggregation.")

    for source in dns_sources:
        name = source.get('name')
        url = source.get('url')
        format_type = source.get('format')  # Potentially use this later

        if not name or not url:
            logging.warning("Skipping DNS source due to missing name or URL.")
            continue

        logging.info(f"Processing source: {name} from {url}")
        content = fetch_content(url)
        if content:
            dns_entries = extract_dns_entries(content)
            all_dns_entries.update(dns_entries)
            logging.info(f"Found {len(dns_entries)} DNS entries from {name}.")

    # Save the aggregated DNS entries
    try:
        with open(output_file, 'w') as f:
            for dns_entry in sorted(list(all_dns_entries)):
                f.write(f"{dns_entry}\n")
        logging.info(f"Successfully aggregated and saved {len(all_dns_entries)} unique DNS entries to {output_file}")
    except IOError as e:
        logging.error(f"Error writing to output file {output_file}: {e}")

if __name__ == "__main__":
    main()