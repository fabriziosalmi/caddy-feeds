import requests
import yaml
import re
import json
import logging
import os
import time
from typing import List, Dict, Any, Optional

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

CONFIG_FILE = 'config.yaml'
OUTPUT_DIR = 'rules'

# Define Intermediate Representation (IR) classes
class ModSecurityRuleIR:
    def __init__(self, rule_id: str, phase: int, variables: List[str], operator: Optional[str], pattern: str, actions: Dict[str, str], original_actions_str: str):
        self.rule_id = rule_id
        self.phase = phase
        self.variables = variables
        self.operator = operator
        self.pattern = pattern
        self.actions = actions
        self.original_actions_str = original_actions_str

    def __repr__(self):
        return f"ModSecurityRuleIR(id={self.rule_id}, phase={self.phase}, vars={self.variables}, op={self.operator}, pattern='{self.pattern}', actions={self.actions})"


def load_config():
    """Loads the configuration from config.yaml."""
    try:
        with open(CONFIG_FILE, 'r') as f:
            config = yaml.safe_load(f)
            if not config:
                raise ValueError("Configuration file is empty.")
            return config
    except FileNotFoundError:
        logging.error(f"Configuration file not found: {CONFIG_FILE}")
        return None
    except (yaml.YAMLError, ValueError) as e:
        logging.error(f"Error parsing configuration file: {e}")
        return None


def fetch_content(url):
    """Fetches the content from a given URL."""
    try:
        response = requests.get(url, timeout=10)
        response.raise_for_status()
        return response.text
    except requests.exceptions.RequestException as e:
        logging.error(f"Error fetching content from {url}: {e}")
        return None


def preprocess_pattern(pattern):
    """Preprocesses regex patterns to ensure they are valid and consistent."""
    if pattern.startswith('@rx'):
        original_pattern = pattern
        pattern = pattern[3:].strip()
        flags = ""
        regex_body = pattern
        flag_matches = re.findall(r'^\(\?([a-z]+)\)', pattern)
        if flag_matches:
            flags = "(?" + flag_matches[0] + ")"
            regex_body = pattern[len(flags):].strip()
        pattern = '@rx ' + flags + regex_body
        if pattern == '@rx ':
            logging.warning(f"Empty regex pattern after @rx: {original_pattern}")
            return '@rx .*'
    while pattern.count('[') > pattern.count(']'):
        logging.warning(f"Unterminated character set, aggressive fix (adding ]): {pattern}")
        pattern += ']'
    pattern = pattern.replace('[CDATA[', '\\[CDATA\\[').replace('\\\\', '\\')
    if pattern.startswith('/') and pattern.endswith('/'):
        pattern = pattern[1:-1]
    return pattern


def extract_rules(rule_text: str, filename: str, stats: Dict[str, int]) -> List[ModSecurityRuleIR]:
    """
    Extracts ModSecurity rules and creates Intermediate Representation (IR).
    Now supports non-@rx operators and assigns synthetic IDs to all rules.
    """
    rules_ir = []
    rule_pattern = r'SecRule\s+([\s\S]+?)"([^"]+)"\s*([\s\S]+?)(?=SecRule|SecAction|SecDefaultAction|SecRuleRemoveTarget|SecRuleUpdateTargetById|SecMarker|^\s*#|$)'

    rule_position = 0  # Track rule position for synthetic IDs

    for match in re.finditer(rule_pattern, rule_text, re.MULTILINE | re.DOTALL):
        stats['total_rules_parsed'] += 1
        rule_position += 1
        rule_id = None
        try:
            variables_str, pattern, actions_str = match.groups()

            variables_str = variables_str.strip()
            pattern = pattern.strip()
            actions_str = actions_str.strip()

            # Handle dynamic variables
            if '%{' in variables_str or '%{' in pattern or '%{' in actions_str:
                variables_str = re.sub(r'%\{[^}]+\}', 'DYNAMIC_VAR', variables_str)
                pattern = re.sub(r'%\{[^}]+\}', 'DYNAMIC_VAR', pattern)
                actions_str = re.sub(r'%\{[^}]+\}', 'DYNAMIC_VAR', actions_str)
                logging.debug(f"Replaced dynamic variables in rule: {pattern}, File: {filename}")

            pattern = preprocess_pattern(pattern)

            # Assign synthetic ID if no explicit ID is found
            rule_id_match = re.search(r'(?i)id:\s*(\d+)', actions_str)
            if rule_id_match:
                rule_id = rule_id_match.group(1)
            else:
                rule_id = f"synthetic-id-{filename.replace('.conf', '')}-{rule_position}"
                logging.debug(f"Assigned synthetic ID '{rule_id}' to rule in {filename} without explicit ID.")

            operator = None
            operator_arg = pattern
            operator_match = re.match(r'@([a-zA-Z]+)\s*(.*)', pattern)
            if operator_match:
                operator = operator_match.group(1)
                operator_arg = operator_match.group(2).strip()
                if operator == 'lt':
                    try:
                        value = int(operator_arg)
                        operator_arg = f"^[0-{value-1}]$"
                    except ValueError:
                        logging.warning(f"Invalid @lt operator in rule {rule_id}: {pattern}, File: {filename}. Skipping.")
                        stats['rules_parse_errors'] += 1
                        continue
                elif operator == 'rx':
                    operator_arg = '@rx ' + operator_arg
                    operator_arg = preprocess_pattern(operator_arg)
                    operator_arg = operator_arg[3:].strip()
                elif operator == 'pm':
                    operator_arg = '|'.join(re.escape(x.strip()) for x in operator_arg.split(','))
                    operator_arg = f'@rx {operator_arg}'
                elif operator == 'streq':
                    operator_arg = f'@rx ^{re.escape(operator_arg)}$'
                elif operator == 'contains':
                    operator_arg = f'@rx {re.escape(operator_arg)}'
                elif operator == 'beginsWith':
                    operator_arg = f'@rx ^{re.escape(operator_arg)}'
                elif operator == 'endsWith':
                    operator_arg = f'@rx {re.escape(operator_arg)}$'
                else:
                    logging.debug(f"Skipping unsupported operator '{operator}' in rule {rule_id}, File: {filename}.")
                    stats['rules_skipped_non_rx_operator'] += 1
                    continue

            if operator_arg.startswith('@rx '):
                regex_pattern_to_validate = operator_arg[3:].strip()
                try:
                    re.compile(regex_pattern_to_validate)
                except re.error as e:
                    logging.warning(f"Invalid regex pattern in rule {rule_id}: {regex_pattern_to_validate}. Error: {e}. Skipping rule.")
                    stats['rules_skipped_invalid_regex'] += 1
                    continue

            variables_list = [v.strip() for v in variables_str.split(',')]

            actions = {}
            for action_part_match in re.finditer(r'([a-zA-Z_]+):[\'"]?([^\'"]*)[\'"]?', actions_str):
                action_name = action_part_match.group(1)
                action_param = action_part_match.group(2)
                actions[action_name] = action_param

            rule_ir = ModSecurityRuleIR(
                rule_id=rule_id,
                phase=int(actions.get('phase', 2)),
                variables=variables_list,
                operator=operator,
                pattern=operator_arg,
                actions=actions,
                original_actions_str=actions_str
            )
            rules_ir.append(rule_ir)

        except Exception as e:
            logging.error(f"Error parsing rule in {filename}: {e}. Raw rule content: {match.group(0)}")
            stats['rules_parse_errors'] += 1
            continue

    return rules_ir


def convert_ir_to_custom_rule(rule_ir: ModSecurityRuleIR, filename: str, stats: Dict[str, int]) -> Optional[Dict[str, Any]]:
    """Converts ModSecurityRuleIR to custom rule format."""
    logging.debug(f"Attempting conversion for Rule IR: {rule_ir}")

    targets = []
    for variable in rule_ir.variables:
        if ":" in variable:
            target_name = variable.split(":")[0].upper()
            if target_name in ["ARGS", "BODY", "URL", "HEADERS", "REQUEST_HEADERS",
                               "RESPONSE_HEADERS", "REQUEST_COOKIES", "USER_AGENT",
                               "CONTENT_TYPE", "X-FORWARDED-FOR", "X-REAL-IP", "URI", 
                               "ARGS_GET", "ARGS_POST", "FILES", "REQUEST_BODY", 
                               "QUERY_STRING", "REQUEST_URI", "REQUEST_METHOD"]:
                targets.append(variable.upper())
                logging.debug(f"  Rule '{rule_ir.rule_id}': Added target (with selector): {variable.upper()}")
        elif variable.upper() in ["ARGS", "BODY", "URL", "HEADERS", "REQUEST_HEADERS",
                                   "RESPONSE_HEADERS", "REQUEST_COOKIES", "USER_AGENT",
                                   "CONTENT_TYPE", "X-FORWARDED-FOR", "X-REAL-IP", "URI", 
                                   "ARGS_GET", "ARGS_POST", "FILES", "REQUEST_BODY", 
                                   "QUERY_STRING", "REQUEST_URI", "REQUEST_METHOD"]:
            targets.append(variable.upper())
            logging.debug(f"  Rule '{rule_ir.rule_id}': Added target (no selector): {variable.upper()}")
        else:
            logging.debug(f"  Rule '{rule_ir.rule_id}': Variable '{variable}' not recognized as target.")

    if not targets:
        logging.debug(f"Skipping rule '{rule_ir.rule_id}' from {filename} - no valid targets after conversion.")
        stats['rules_skipped_no_targets'] += 1
        return None

    # Handle pattern conversion
    pattern = rule_ir.pattern
    logging.debug(f"  Rule '{rule_ir.rule_id}': Original pattern: '{pattern}'")

    # Remove @rx prefix if present
    if pattern.startswith('@rx '):
        pattern = pattern[4:].strip()
        logging.debug(f"  Rule '{rule_ir.rule_id}': Removed @rx prefix. New pattern: '{pattern}'")

    # Handle negation (e.g., !@rx)
    if pattern.startswith('!@rx '):
        pattern = pattern[5:].strip()
        pattern = f"^(?!{pattern}).*"  # Convert negation to a negative lookahead regex
        logging.debug(f"  Rule '{rule_ir.rule_id}': Converted negation to regex. New pattern: '{pattern}'")

    # Validate the final regex pattern
    try:
        re.compile(pattern)
    except re.error as e:
        logging.warning(f"Invalid regex pattern in rule {rule_ir.rule_id}: {pattern}. Error: {e}. Skipping rule.")
        stats['rules_skipped_invalid_regex'] += 1
        return None

    severity_val = rule_ir.actions.get('severity', 'LOW').upper()
    action_val = rule_ir.actions.get('action', 'log').lower()
    description_val = rule_ir.actions.get('msg', 'No description provided.')

    score = 0
    if action_val == "pass":
        score = 1
    elif action_val == "block":
        score_map = {"CRITICAL": 10, "HIGH": 9, "MEDIUM": 7, "LOW": 5}
        score = score_map.get(severity_val, 8)
    elif action_val == "log":
        score_map_log = {"CRITICAL": 6, "HIGH": 5, "MEDIUM": 3, "LOW": 1}
        score = score_map_log.get(severity_val, 2)

    custom_rule = {
        "id": rule_ir.rule_id,
        "phase": rule_ir.phase,
        "pattern": pattern,  # Use the cleaned pattern
        "targets": targets,
        "severity": severity_val,
        "action": action_val,
        "score": score,
        "description": description_val
    }

    logging.debug(f"  Rule '{rule_ir.rule_id}': Successfully converted to custom rule: {custom_rule}")
    return custom_rule


def download_owasp_rules(repo_url, rules_dir, stats):
    """Downloads and processes OWASP rules, updating statistics."""
    all_rules_with_filenames = []
    headers = {}

    try:
        api_url = f"https://api.github.com/repos/{repo_url}/contents/{rules_dir}"
        response = requests.get(api_url, headers=headers)
        response.raise_for_status()

        for file in response.json():
            if not file['name'].endswith('.conf'):
                continue

            time.sleep(0.5)
            response = requests.get(file["download_url"], headers=headers)
            response.raise_for_status()
            logging.info(f"Processing rule file: {file['name']}")

            rules_ir = extract_rules(response.text, file['name'], stats)
            all_rules_with_filenames.append((file['name'], rules_ir))

    except requests.exceptions.RequestException as e:
        logging.error(f"Error downloading OWASP rules: {e}")
    return all_rules_with_filenames


def main():
    """Main function to aggregate and save OWASP rules with statistics."""
    config = load_config()
    if not config:
        return

    os.makedirs(OUTPUT_DIR, exist_ok=True)
    logging.info("Starting OWASP rules aggregation.")

    stats = {
        'total_rules_parsed': 0,
        'rules_successfully_converted': 0,
        'rules_parsed_but_skipped_low_priority': 0,
        'rules_skipped_no_id': 0,
        'rules_skipped_invalid_regex': 0,
        'rules_skipped_dynamic_variable': 0,
        'rules_skipped_no_targets': 0,
        'rules_skipped_generic_pattern': 0,
        'rules_skipped_non_rx_operator': 0,
        'rules_parse_errors': 0
    }

    crs_repo_url = "coreruleset/coreruleset"
    crs_rules_dir = "rules"
    logging.getLogger().setLevel(logging.DEBUG)  # DEBUG for rule processing
    all_crs_rules_with_filenames = download_owasp_rules(crs_repo_url, crs_rules_dir, stats)
    logging.getLogger().setLevel(logging.INFO)  # Reset to INFO

    aggregated_rules = []
    logging.info("Saving OWASP CRS rules into individual files in the rules directory.")
    for filename, rules_ir in all_crs_rules_with_filenames:
        custom_rules = []
        for rule_ir in rules_ir:
            custom_rule = convert_ir_to_custom_rule(rule_ir, filename, stats)
            if custom_rule:
                severity_val = custom_rule['severity']
                if severity_val in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:  # Include LOW severity
                    custom_rules.append(custom_rule)
                    stats['rules_successfully_converted'] += 1
                    logging.debug(f"  Rule '{custom_rule['id']}' of severity '{severity_val}' successfully converted and added.")
                else:
                    stats['rules_parsed_but_skipped_low_priority'] += 1
            elif custom_rule is None:
                if rule_ir.operator == 'rx':
                    if rule_ir.pattern == '.*':
                        stats['rules_skipped_generic_pattern'] += 1
                    else:
                        stats['rules_skipped_no_targets'] += 1
                elif rule_ir.operator != 'rx':  # Count rules skipped for non-rx operator
                    stats['rules_skipped_non_rx_operator'] += 1
                else:  # other reasons for None return (though now unlikely)
                    stats['rules_skipped_no_targets'] += 1

        output_file = os.path.join(OUTPUT_DIR, f"{filename.replace('.conf', '')}.json")
        try:
            with open(output_file, 'w') as f:
                json.dump(custom_rules, f, indent=2)
            logging.info(f"Successfully saved {len(custom_rules)} rules from {filename} to {output_file}")
            aggregated_rules.extend(custom_rules)
        except IOError as e:
            logging.error(f"Error writing to output file {output_file}: {e}")

    output_file = os.path.join(OUTPUT_DIR, "rules.json")
    try:
        with open(output_file, 'w') as f:
            json.dump(aggregated_rules, f, indent=2)
        logging.info(f"Successfully saved all aggregated rules to {output_file}")
    except IOError as e:
        logging.error(f"Error writing to aggregated output file {output_file}: {e}")

    logging.info("OWASP rules aggregation complete.")
    logging.info("--- Rule Conversion Statistics ---")
    for key, value in stats.items():
        logging.info(f"{key}: {value}")
    logging.info("--- End Statistics ---")


if __name__ == "__main__":
    main()