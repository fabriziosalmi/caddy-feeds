import requests
import re
import json
import logging
from typing import List, Dict, Optional
from pathlib import Path

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Constants
NAXSI_RULES_URL = "https://raw.githubusercontent.com/nbs-system/naxsi/master/naxsi_config/naxsi_core.rules"
OUTPUT_FILE = "naxsi_rules.json"

def fetch_naxsi_rules(url: str) -> Optional[str]:
    """
    Fetches the latest NAXSI rules from the given URL.

    Args:
        url (str): The URL to fetch the NAXSI rules from.

    Returns:
        Optional[str]: The raw content of the NAXSI rules file.
    """
    try:
        response = requests.get(url, timeout=10)
        response.raise_for_status()
        content = response.text
        logging.debug(f"Fetched NAXSI rules content:\n{content}")  # Debug statement
        return content
    except requests.exceptions.RequestException as e:
        logging.error(f"Error fetching NAXSI rules from {url}: {e}")
    return None

def convert_naxsi_rule(naxsi_rule: str) -> Optional[Dict]:
    """
    Converts a single NAXSI MainRule into Caddy WAF format.

    Args:
        naxsi_rule (str): The NAXSI rule to convert.

    Returns:
        Optional[Dict]: The converted rule in Caddy WAF format, or None if the rule is invalid.
    """
    match = re.search(
        r'MainRule\s+"(rx:[^"]+|str:[^"]+)"\s+"msg:([^"]+)"\s+"mz:([^"]+)"\s+"s:\$[^:]+:(\d+)"\s+id:(\d+);',
        naxsi_rule
    )
    if not match:
        logging.warning(f"Skipping invalid NAXSI rule: {naxsi_rule}")
        return None

    pattern, description, mz, score, rule_id = match.groups()
    score = int(score)

    targets = []
    for part in mz.split("|"):
        if part.startswith("$HEADERS_VAR:"):
            targets.append(f"HEADERS:{part[13:]}")
        elif part in ["ARGS", "BODY", "URL"]:
            targets.append(part)

    rule = {
        "id": rule_id,
        "phase": 2,  # Default phase for request inspection
        "pattern": pattern.replace("str:", "").replace("rx:", ""),  # Remove 'str:' or 'rx:'
        "targets": targets,
        "severity": "HIGH" if score >= 8 else "MEDIUM",  # Set severity based on score
        "action": "block",  # Default action
        "score": score,  # Use the score from the rule
        "description": description
    }

    return rule

def convert_all_naxsi_rules(rules_content: str) -> List[Dict]:
    """
    Converts all NAXSI rules into Caddy WAF format.

    Args:
        rules_content (str): The raw content of the NAXSI rules file.

    Returns:
        List[Dict]: A list of converted rules in Caddy WAF format.
    """
    caddy_rules = []
    for line in rules_content.splitlines():
        line = line.strip()
        if line.startswith("MainRule"):
            logging.debug(f"Processing NAXSI rule: {line}")
            converted_rule = convert_naxsi_rule(line)
            if converted_rule:
                caddy_rules.append(converted_rule)
    return caddy_rules

def save_rules_to_file(rules: List[Dict], output_file: str):
    """
    Saves the converted rules to a JSON file.

    Args:
        rules (List[Dict]): The list of rules to save.
        output_file (str): The path to the output JSON file.
    """
    try:
        output_path = Path(output_file)
        with output_path.open("w") as f:
            json.dump(rules, f, indent=2)
        logging.info(f"Successfully saved {len(rules)} rules to {output_file}")
    except IOError as e:
        logging.error(f"Error writing to output file {output_file}: {e}")

def main():
    """
    Main function to fetch, convert, and save NAXSI rules.
    """
    logging.info("Fetching NAXSI rules...")
    naxsi_rules_content = fetch_naxsi_rules(NAXSI_RULES_URL)
    if not naxsi_rules_content:
        logging.error("Failed to fetch NAXSI rules. Exiting.")
        return

    logging.info("Converting NAXSI rules to Caddy WAF format...")
    caddy_rules = convert_all_naxsi_rules(naxsi_rules_content)

    if not caddy_rules:
        logging.warning("No valid NAXSI rules found. Check the rules file format.")
        return

    logging.info("Saving converted rules...")
    save_rules_to_file(caddy_rules, OUTPUT_FILE)

if __name__ == "__main__":
    main()