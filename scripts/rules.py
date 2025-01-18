import requests
import yaml
import re
import json
import logging
import os
import time
import glob
import warnings
from typing import List, Dict, Tuple, Any

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Suppress DeprecationWarnings
warnings.filterwarnings("ignore", category=DeprecationWarning)


CONFIG_FILE = 'config.yaml'
OUTPUT_DIR = 'rules'

def load_config() -> Dict[str, Any]:
    """Loads the configuration from config.yaml."""
    try:
        with open(CONFIG_FILE, 'r') as f:
            config = yaml.safe_load(f)
            if not isinstance(config, dict):
                raise yaml.YAMLError("Configuration file must contain a dictionary.")
            return config
    except FileNotFoundError:
        logging.error(f"Configuration file not found: {CONFIG_FILE}")
        return {}
    except yaml.YAMLError as e:
        logging.error(f"Error parsing configuration file: {e}")
        return {}

def fetch_content(url: str) -> str:
    """Fetches the content from a given URL."""
    try:
        response = requests.get(url, timeout=10)
        response.raise_for_status()  # Raise HTTPError for bad responses (4xx or 5xx)
        return response.text
    except requests.exceptions.RequestException as e:
        logging.error(f"Error fetching content from {url}: {e}")
        return ""

def preprocess_pattern(pattern: str) -> str:
    """
    Preprocesses the regex pattern to ensure flags like (?i) are at the start.
    Also handles special cases like [CDATA[] and unterminated character sets.
    """
    if pattern.startswith('@rx'):
        pattern_part = pattern[3:].strip()
        flags = []
        for flag in ['(?i)', '(?is)', '(?s)']:
            if flag in pattern_part:
                flags.append(flag)
                pattern_part = pattern_part.replace(flag, '')
        if flags:
            pattern_part = ''.join(flags) + pattern_part
        pattern = '@rx ' + pattern_part

    if '[' in pattern and ']' not in pattern:
        logging.warning(f"Unterminated character set in pattern: {pattern}")
        pattern += ']'

    pattern = pattern.replace('[CDATA[', '\\[CDATA\\[')
    return pattern

def extract_rules(rule_text: str) -> List[Dict[str, Any]]:
    """
    Extracts individual ModSecurity rules from rule file content using regex.
    """
    rules = []
    rule_pattern = r'SecRule\s+([^"]*)"([^"]+)"\s*(\\\s*\n\s*.*?|.*?)(?=\s*SecRule|\s*$)'

    for match in re.finditer(rule_pattern, rule_text, re.MULTILINE | re.DOTALL):
        try:
            variables, pattern, actions = match.groups()
            pattern = preprocess_pattern(pattern)

            rule_id_match = re.search(r'id:(\d+)', actions)
            if not rule_id_match:
                continue
            rule_id = rule_id_match.group(1)

            try:
                re.compile(pattern)
            except re.error as e:
                logging.warning(f"Invalid regex pattern in rule {rule_id}: {pattern}. Error: {e}")
                continue

            targets = []
            if variables:
                for target in ["ARGS", "BODY", "URL", "HEADERS", "REQUEST_HEADERS",
                                "RESPONSE_HEADERS", "REQUEST_COOKIES", "USER_AGENT",
                                "CONTENT_TYPE", "X-FORWARDED-FOR", "X-REAL-IP"]:
                    if re.search(rf'(?i)\b{target}\b', variables):
                        targets.append(target)

            # Skip rule if no targets are found
            if not targets:
               logging.debug(f"Skipping rule '{rule_id}' because it has no targets.")
               continue


            severity_match = re.search(r'severity:\'?([^,\'\s]+)', actions)
            action_match = re.search(r'action:\'?([^,\'\s]+)', actions)
            description_match = re.search(r'msg:\'?([^\']+)\'', actions)

            severity_val = severity_match.group(1) if severity_match else "LOW"
            action_val = action_match.group(1) if action_match else "log"
            description_val = description_match.group(1) if description_match else "No description provided."

            score = 0 if action_val == "pass" else \
                    5 if action_val == "block" else \
                    4 if severity_val.upper() == "HIGH" else \
                    3 if severity_val.upper() == "MEDIUM" else 1

            rule = {
                "id": rule_id,
                "phase": int(re.search(r'phase:(\d+)', actions).group(1)) if re.search(r'phase:(\d+)', actions) else 2,
                "pattern": pattern,
                "targets": targets,
                "severity": severity_val,
                "action": action_val,
                "score": score,
                "description": description_val
            }
            rules.append(rule)

        except (AttributeError, ValueError, re.error) as e:
            logging.warning(f"Error parsing rule: {e}")
            continue

    return rules

def download_owasp_rules(repo_url: str, rules_dir: str) -> List[Tuple[str, List[Dict[str, Any]]]]:
    """
    Downloads and processes OWASP ModSecurity Core Rule Set (CRS) files from GitHub.
    """
    all_rules_with_filenames = []
    headers = {}

    try:
        api_url = f"https://api.github.com/repos/{repo_url}/contents/{rules_dir}"
        response = requests.get(api_url, headers=headers)
        response.raise_for_status()

        for file in response.json():
            if not file['name'].endswith('.conf'):
                continue

            time.sleep(1)
            response = requests.get(file["download_url"], headers=headers)
            response.raise_for_status()
            logging.info(f"Processing rule file: {file['name']}")
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

    crs_repo_url = "coreruleset/coreruleset"
    crs_rules_dir = "rules"
    all_crs_rules_with_filenames = download_owasp_rules(crs_repo_url, crs_rules_dir)

    aggregated_rules = []
    logging.info("Saving OWASP CRS rules into individual files in the rules directory.")
    for filename, rules in all_crs_rules_with_filenames:
        output_file = os.path.join(OUTPUT_DIR, f"{filename.replace('.conf', '')}.json")
        try:
            with open(output_file, 'w') as f:
                json.dump(rules, f, indent=2)
            logging.info(f"Successfully saved {len(rules)} rules from {filename} to {output_file}")
            aggregated_rules.extend(rules)
        except IOError as e:
            logging.error(f"Error writing to output file {output_file}: {e}")

    output_file = os.path.join(OUTPUT_DIR, "rules.json")
    try:
        with open(output_file, 'w') as f:
           json.dump(aggregated_rules, f, indent=2)
        logging.info(f"Successfully saved all aggregated rules to {output_file}")
        
        # Validate rules in rules.json
        validate_rules(output_file)
    except IOError as e:
        logging.error(f"Error writing to aggregated output file {output_file}: {e}")

    logging.info("OWASP rules aggregation complete.")

def validate_rules(file_path: str) -> None:
    """
    Validates the loaded rules by checking if each rule has targets.
    """
    try:
        with open(file_path, 'r') as f:
            rules = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError) as e:
        logging.error(f"Error loading or parsing rules from {file_path}: {e}")
        return

    invalid_rules = []
    for index, rule in enumerate(rules):
      if not rule.get('targets'):
        invalid_rules.append(f"Rule at index {index}: rule '{rule.get('id', 'unknown')}' has no targets")


    if invalid_rules:
        logging.warning(f"Some rules failed validation    {{\"file\": \"{file_path}\", \"invalid_rules\": {invalid_rules}}}")
    logging.info(f"Rules loaded    {{\"file\": \"{file_path}\", \"total_rules\": {len(rules)}, \"invalid_rules\": {len(invalid_rules)}}}")
    if invalid_rules:
        logging.warning(f"Some rules across files failed validation       {{\"invalid_rules\": {invalid_rules}}}")


if __name__ == "__main__":
    main()
