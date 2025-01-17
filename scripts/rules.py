import requests
import yaml
import re
import json
import logging
import os
import time

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

CONFIG_FILE = 'config.yaml'
OUTPUT_DIR = 'rules'

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

def extract_rules(rule_text):
    """
    Extracts individual ModSecurity rules from rule file content using regex.

    Args:
        rule_text (str): Content of ModSecurity rule file

    Returns:
        list: List of dictionaries containing parsed rule information
    """
    rules = []
    # Regex pattern to match ModSecurity SecRule directives
    rule_pattern = r'SecRule\s+([^"]*)"([^"]+)"\s*(\\\s*\n\s*.*?|.*?)(?=\s*SecRule|\s*$)'

    for match in re.finditer(rule_pattern, rule_text, re.MULTILINE | re.DOTALL):
        try:
            variables, pattern, actions = match.groups()

            # Extract key rule properties using regex
            rule_id = re.search(r'id:(\d+)', actions)
            severity = re.search(r'severity:\'?([^,\'\s]+)', actions)
            action = re.search(r'action:\'?([^,\'\s]+)', actions)
            phase = re.search(r'phase:(\d+)', actions)
            description = re.search(r'msg:\'?([^\']+)\'', actions)

            if not rule_id:
                continue

            # Handle special characters in pattern
            pattern = pattern.replace('[CDATA[', '\\[CDATA\\[')

            # Validate regex pattern
            try:
                re.compile(pattern)
            except re.error:
                logging.warning(f"Invalid regex pattern in rule {rule_id.group(1)}: {pattern}")
                continue

            # Extract targeted variables from rule
            targets = []
            if variables:
                # List of possible ModSecurity variables to check for
                for target in ["ARGS", "BODY", "URL", "HEADERS", "REQUEST_HEADERS",
                             "RESPONSE_HEADERS", "REQUEST_COOKIES", "USER_AGENT",
                             "CONTENT_TYPE", "X-FORWARDED-FOR", "X-REAL-IP"]:
                    if target in variables.upper():
                        targets.append(target)

            # Set default values if properties are missing
            severity_val = severity.group(1) if severity else "LOW"
            action_val = action.group(1) if action else "log"
            description_val = description.group(1) if description else "No description provided."

            # Calculate rule score based on severity and action
            score = 0 if action_val == "pass" else \
                    5 if action_val == "block" else \
                    4 if severity_val.upper() == "HIGH" else \
                    3 if severity_val.upper() == "MEDIUM" else 1

            # Create rule dictionary with extracted information
            rule = {
                "id": rule_id.group(1),
                "phase": int(phase.group(1)) if phase else 2,
                "pattern": pattern,
                "targets": targets,
                "severity": severity_val,
                "action": action_val,
                "score": score,
                "description": description_val
            }
            rules.append(rule)

        except (AttributeError, ValueError) as e:
            continue

    return rules

def download_owasp_rules(repo_url, rules_dir):
    """
    Downloads and processes OWASP ModSecurity Core Rule Set (CRS) files from GitHub.

    Args:
        repo_url (str): GitHub repository path (e.g., 'coreruleset/coreruleset')
        rules_dir (str): Directory containing rule files in the repository

    Returns:
        list: A list of tuples, where each tuple contains the filename and a list of its rules.
    """
    all_rules_with_filenames = []
    headers = {}  # Can be used to add GitHub API token if needed

    try:
        # Construct GitHub API URL to list contents of rules directory
        api_url = f"https://api.github.com/repos/{repo_url}/contents/{rules_dir}"
        response = requests.get(api_url, headers=headers)
        response.raise_for_status()

        # Process each .conf file in the directory
        for file in response.json():
            if not file['name'].endswith('.conf'):
                continue

            # Add delay to avoid hitting GitHub API rate limits
            time.sleep(1)
            response = requests.get(file["download_url"], headers=headers)
            response.raise_for_status()
            logging.info(f"Processing rule file: {file['name']}")

            # Extract rules from file content
            rules = extract_rules(response.text)
            all_rules_with_filenames.append((file['name'], rules))

    except requests.exceptions.RequestException as e:
        logging.error(f"Error downloading OWASP rules: {e}")
    return all_rules_with_filenames

def main():
    """Main function to aggregate and save OWASP rules."""
    config = load_config()
    if not config:
        return

    os.makedirs(OUTPUT_DIR, exist_ok=True)

    logging.info("Starting OWASP rules aggregation.")

    # Download OWASP CRS rules
    crs_repo_url = "coreruleset/coreruleset"
    crs_rules_dir = "rules"
    all_crs_rules_with_filenames = download_owasp_rules(crs_repo_url, crs_rules_dir)

    # Save OWASP CRS rules
    logging.info("Saving OWASP CRS rules into individual files in the rules directory.")
    for filename, rules in all_crs_rules_with_filenames:
        output_file = os.path.join(OUTPUT_DIR, f"{filename.replace('.conf', '')}.json")
        try:
            with open(output_file, 'w') as f:
                json.dump(rules, f, indent=2)
            logging.info(f"Successfully saved {len(rules)} rules from {filename} to {output_file}")
        except IOError as e:
            logging.error(f"Error writing to output file {output_file}: {e}")

    # TODO: Add logic to process other rule sources from config.yaml if needed
    # (e.g., using fetch_content and potentially different parsing logic)

    logging.info("OWASP rules aggregation complete.")

if __name__ == "__main__":
    main()