from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional
import requests
from requests.adapters import HTTPAdapter
import yaml
import re
import json
import logging
import os
import sys
import time
from urllib3.util import Retry
from functools import lru_cache
from abc import ABC, abstractmethod
from prometheus_client import Counter, Histogram, start_http_server

# Custom exceptions
class RuleProcessingError(Exception):
    """Base exception for rule processing errors."""
    pass

class ConfigurationError(RuleProcessingError):
    """Configuration related errors."""
    pass

class FetchError(RuleProcessingError):
    """Content fetching related errors."""
    pass

# Add performance metrics
RULES_PROCESSED = Counter('rules_processed_total', 'Number of rules processed')
PROCESSING_TIME = Histogram('rule_processing_seconds', 'Time spent processing rules')

@dataclass
class Config:
    repo_url: str = "default_repo_url"  # Add default value for repo_url
    rules_dir: str = ""
    output_dir: str = ""
    min_severity: str = "LOW"
    request_timeout: int = 10
    max_retries: int = 3
    metrics_port: Optional[int] = None
    cache_ttl: int = 3600  # Add cache TTL
    ip_lists: Optional[List[str]] = field(default_factory=list)  # Add ip_lists field
    owasp_rules: Optional[Dict[str, Any]] = None   # Added new field for extra rule sources
    nasxi_rules: Optional[Dict[str, Any]] = None   # Added new field for nasxi rule sources
    base_rules: Optional[Dict[str, Any]] = None      # Added new field for base rules support
    
    def validate(self) -> None:
        """Validate configuration values"""
        if not self.repo_url or not self.rules_dir or not self.output_dir:
            raise ConfigurationError("Missing required configuration fields")
        if self.request_timeout < 1:
            raise ConfigurationError("Request timeout must be positive")
        if self.max_retries < 0:
            raise ConfigurationError("Max retries cannot be negative")

    @classmethod
    def from_yaml(cls, path: str) -> 'Config':
        try:
            with open(path, 'r') as f:
                data = yaml.safe_load(f)
            # Remove 'dns_lists' if it exists in the data
            data.pop('dns_lists', None)
            return cls(**data)
        except Exception as e:
            raise ConfigurationError(f"Failed to load config: {e}")

@dataclass
class ModSecurityRuleIR:
    rule_id: str
    phase: int
    variables: List[str]
    operator: Optional[str]
    pattern: str
    actions: Dict[str, str]
    original_actions_str: str
    filename: str = field(default="")

class HttpClient:
    def __init__(self, timeout: int = 10, max_retries: int = 3):
        self.session = requests.Session()
        retry_strategy = Retry(
            total=max_retries,
            backoff_factor=1,
            status_forcelist=[429, 500, 502, 503, 504],
        )
        adapter = HTTPAdapter(max_retries=retry_strategy)
        self.session.mount("https://", adapter)
        self.session.mount("http://", adapter)
        self.timeout = timeout

    def get(self, url: str) -> str:
        try:
            response = self.session.get(url, timeout=self.timeout)
            response.raise_for_status()
            return response.text
        except requests.exceptions.RequestException as e:
            raise FetchError(f"Failed to fetch {url}: {e}")

class RuleProcessor(ABC):
    @abstractmethod
    def process_rule(self, rule: ModSecurityRuleIR) -> Optional[Dict[str, Any]]:
        pass

class ModSecurityRuleProcessor(RuleProcessor):
    def __init__(self, config: Config):
        self.config = config
        self.logger = logging.getLogger(__name__)
        self.cache = {}  # Add caching
        self.metrics_port = config.metrics_port or 9090
        start_http_server(self.metrics_port)

    @lru_cache(maxsize=1000)
    def preprocess_pattern(self, pattern: str) -> str:
        if not isinstance(pattern, str):
            raise ValueError(f"Pattern must be string, got {type(pattern)}")
            
        if not pattern:
            return '@rx .*'
            
        if pattern.startswith('@rx'):
            pattern = pattern[3:].strip()
            flags = re.match(r'^\(\?([a-z]+)\)', pattern)
            flags_str = flags.group(0) if flags else ''
            regex_body = pattern[len(flags_str):] if flags else pattern
            
            # Validate regex before returning
            try:
                re.compile(regex_body)
            except re.error as e:
                logging.warning(f"Invalid regex pattern '{regex_body}' in rule '{pattern}', using safe fallback: {e}")
                return '@rx .*'
                
            pattern = '@rx ' + flags_str + regex_body.strip()

        # Fix common regex issues
        pattern = (pattern.replace('[CDATA[', '\\[CDATA\\[')
                        .replace('\\\\', '\\')
                        .strip('/'))
                        
        if pattern.startswith('@lt'):
            try:
                value = int(pattern[3:].trip())
                pattern = f'@rx ^[0-{value-1}]$'
            except ValueError:
                logging.warning(f"Invalid @lt operator in pattern '{pattern}', using safe fallback.")
                return '@rx .*'
                
        # Additional validation for common issues
        try:
            re.compile(pattern)
        except re.error as e:
            logging.warning(f"Invalid regex pattern '{pattern}', using safe fallback: {e}")
            return '@rx .*'
                
        return pattern

    @PROCESSING_TIME.time()
    def process_rule(self, rule: ModSecurityRuleIR) -> Optional[Dict[str, Any]]:
        # Updated branch to support both "nasxi" and "nasxia" operator names
        if rule.operator in ('nasxi', 'nasxia'):
            pattern = rule.pattern.replace('nasxi:', '').replace('nasxia:', '').strip()
            severity_val = rule.actions.get('severity', 'MEDIUM').upper()
            action_val = rule.actions.get('action', 'alert').lower()
            description_val = rule.actions.get('msg', 'Nasxi rule conversion.')
            score = 6 if action_val == "alert" else 5
            custom_rule = {
                "id": rule.rule_id,
                "phase": rule.phase,
                "pattern": pattern,
                "targets": [],  # Nasxi rules may not have targets
                "severity": severity_val,
                "action": action_val,
                "score": score,
                "description": description_val
            }
            self.cache[f"nasxi:{rule.rule_id}"] = custom_rule
            RULES_PROCESSED.inc()
            return custom_rule
        # Cache check
        cache_key = f"{rule.rule_id}:{rule.pattern}"
        if cache_key in self.cache:
            return self.cache[cache_key]

        logging.debug(f"Attempting conversion for Rule IR: {rule}")

        targets = []
        for variable in rule.variables:
            if ":" in variable:
                target_name = variable.split(":")[0].upper()
                if target_name in ["ARGS", "BODY", "URL", "HEADERS", "REQUEST_HEADERS",
                                "RESPONSE_HEADERS", "REQUEST_COOKIES", "USER_AGENT",
                                "CONTENT_TYPE", "X-FORWARDED-FOR", "X-REAL-IP", "URI", 
                                "ARGS_GET", "ARGS_POST", "FILES", "REQUEST_BODY", 
                                "QUERY_STRING", "REQUEST_URI", "REQUEST_METHOD"]:
                    targets.append(variable.upper())
                    logging.debug(f"  Rule '{rule.rule_id}': Added target (with selector): {variable.upper()}")
            elif variable.upper() in ["ARGS", "BODY", "URL", "HEADERS", "REQUEST_HEADERS",
                                    "RESPONSE_HEADERS", "REQUEST_COOKIES", "USER_AGENT",
                                    "CONTENT_TYPE", "X-FORWARDED-FOR", "X-REAL-IP", "URI", 
                                    "ARGS_GET", "ARGS_POST", "FILES", "REQUEST_BODY", 
                                    "QUERY_STRING", "REQUEST_URI", "REQUEST_METHOD"]:
                targets.append(variable.upper())
                logging.debug(f"  Rule '{rule.rule_id}': Added target (no selector): {variable.upper()}")
            else:
                logging.debug(f"  Rule '{rule.rule_id}': Variable '{variable}' not recognized as target.")

        if not targets:
            # Intelligent conversion for no target, generic, and non-rx rules
            if rule.operator == 'rx' and rule.pattern == '.*':
                targets = ["HEADERS:User-Agent"]
                rule.pattern = "(?i)(nikto|sqlmap|nmap|acunetix|nessus|openvas|wpscan|dirbuster|burpsuite|owasp zap|netsparker|appscan|arachni|skipfish|gobuster|wfuzz|hydra|metasploit|nessus|openvas|qualys|zap|w3af|openwebspider|netsparker|appspider|rapid7|nessus|qualys|nuclei|zgrab|vega|gospider|gxspider|whatweb|xspider|joomscan|uniscan|blindelephant)"
                rule.actions['severity'] = 'CRITICAL'
                rule.actions['action'] = 'block'
                rule.actions['msg'] = 'Block traffic from known vulnerability scanners and penetration testing tools.'
                logging.debug(f"  Rule '{rule.rule_id}': Converted to block scanners rule.")
            elif rule.operator == 'rx' and rule.pattern == '^$':
                targets = ["BODY"]
                rule.actions['severity'] = 'LOW'
                rule.actions['action'] = 'log'
                rule.actions['msg'] = 'Log requests with empty body.'
                logging.debug(f"  Rule '{rule.rule_id}': Converted to log empty body rule.")
            else:
                logging.debug(f"Skipping rule '{rule.rule_id}' from {rule.filename} - no valid targets after conversion.")
                return None

        # --- Added intelligence heuristics ---
        if rule.operator == 'rx':
            if re.search(r'(?i)(nikto|sqlmap|nmap|acunetix|nessus|openvas|wpscan|dirbuster|burpsuite|owasp zap)', rule.pattern):
                rule.actions['severity'] = 'CRITICAL'
                rule.actions['action'] = 'block'
                rule.actions['msg'] = 'Block traffic from known vulnerability scanners and penetration testing tools.'
            elif re.search(r'(?i)(Mozilla|Chrome|Safari|Edge|Firefox|Opera|Googlebot|Bingbot|Slurp|DuckDuckBot)', rule.pattern):
                rule.actions['severity'] = 'LOW'
                rule.actions['action'] = 'log'
                rule.actions['msg'] = 'Allow and log traffic from legitimate browsers, search engine crawlers, and social media bots.'
            elif rule.pattern == '^$':
                rule.actions['severity'] = 'LOW'
                rule.actions['action'] = 'log'
                rule.actions['msg'] = 'Log requests with empty body that may indicate missing login form fields.'
        # --- End Added intelligence heuristics ---

        # Remove @rx prefix from pattern
        pattern = rule.pattern
        if pattern.startswith('@rx '):
            pattern = pattern[4:].strip()
        logging.debug(f"  Rule '{rule.rule_id}': Using pattern: '{pattern}'")

        # Set severity and action
        severity_val = rule.actions.get('severity', 'LOW').upper()
        action_val = rule.actions.get('action', 'log').lower()
        description_val = rule.actions.get('msg', 'No description provided.')

        # Improve description if possible
        if "internal dummy connection" in pattern.lower():
            description_val = "Detects internal dummy connections in the User-Agent header."

        # Calculate score
        score = 0
        if action_val == "pass":
            score = 1
        elif action_val == "block":
            score_map = {"CRITICAL": 10, "HIGH": 9, "MEDIUM": 7, "LOW": 5}
            score = score_map.get(severity_val, 8)
        elif action_val == "log":
            score_map_log = {"CRITICAL": 6, "HIGH": 5, "MEDIUM": 3, "LOW": 1}
            score = score_map_log.get(severity_val, 2)

        # Build the custom rule
        custom_rule = {
            "id": rule.rule_id,
            "phase": rule.phase,
            "pattern": pattern,
            "targets": targets,
            "severity": severity_val,
            "action": action_val,
            "score": score,
            "description": description_val
        }

        logging.debug(f"  Rule '{rule.rule_id}': Successfully converted to custom rule: {custom_rule}")

        result = custom_rule
        if result:
            self.cache[cache_key] = result
            RULES_PROCESSED.inc()
        
        return result

    def extract_rules(self, rule_text: str, filename: str) -> List[ModSecurityRuleIR]:
        rules_ir = []
        
        # Regular expression to match SecRule directives
        rule_pattern = r'SecRule\s+([\s\S]+?)"([^"]+)"\s*([\s\S]+?)(?=SecRule|SecAction|SecDefaultAction|SecRuleRemoveTarget|SecRuleUpdateTargetById|SecMarker|^\s*#|$)'
        
        for match in re.finditer(rule_pattern, rule_text):
            try:
                variables_str = match.group(1)
                pattern = match.group(2)
                actions_str = match.group(3)
                
                # Extract rule ID from actions
                rule_id = None
                id_match = re.search(r'id:(\d+)', actions_str)
                if id_match:
                    rule_id = id_match.group(1)
                else:
                    continue

                operator = None
                operator_arg = pattern
                operator_match = re.match(r'@([a-zA-Z]+)\s*(.*)', pattern)
                try:
                    operator = operator_match.group(1)
                    operator_arg = operator_match.group(2).strip()
                    if operator == 'lt':
                        try:
                            value = int(operator_arg)
                            operator_arg = f'@rx ^[0-{value - 1}]$'
                        except ValueError:
                            logging.warning(f"Invalid @lt operator in rule {rule_id}, using safe fallback.")
                            operator_arg = '@rx .*'
                    elif operator == 'rx':
                        operator_arg = '@rx ' + operator_arg
                        operator_arg = self.preprocess_pattern(operator_arg)
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
                        operator_arg = f'@rx ^{re.escape(operator_arg)}$'
                    elif operator == 'eq':
                        operator_arg = f'@rx ^{re.escape(operator_arg)}$'
                    elif operator == 'ge':
                        operator_arg = f'@rx ^[{operator_arg}-9]$'
                    elif operator == 'le':
                        operator_arg = f'@rx ^[0-{operator_arg}]$'
                    else:
                        logging.debug(f"Skipping unsupported operator '{operator}' in rule {rule_id}, File: {filename}.")
                        self.stats.increment('rules_skipped_non_rx_operator')
                        continue
                except (AttributeError, IndexError) as e:
                    logging.debug(f"Failed to parse operator in rule {rule_id}, File: {filename}: {e}")
                    operator = 'rx'
                    operator_arg = pattern

                regex_pattern_to_validate = operator_arg[3:].strip()
                try:
                    re.compile(regex_pattern_to_validate)
                except re.error as e:
                    logging.warning(f"Invalid regex pattern in rule {rule_id}: {regex_pattern_to_validate}. Error: {e}. Using safe fallback.")
                    operator_arg = '@rx .*'
                    self.stats.increment('rules_skipped_invalid_regex')

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
                    original_actions_str=actions_str,
                    filename=filename
                )
                rules_ir.append(rule_ir)

            except Exception as e:
                logging.error(f"Error parsing rule in {filename}: {e}. Raw rule content: {match.group(0)}")
                self.stats.increment('rules_parse_errors')
                continue

        return rules_ir

    def write_rules(self, rules: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        aggregated_rules = []
        logging.info("Saving OWASP CRS and Nasxi rules into individual files.")
        for filename, rules_ir in rules:
            custom_rules = []
            for rule_ir in rules_ir:
                custom_rule = self.rule_processor.process_rule(rule_ir)
                if custom_rule:
                    severity_val = custom_rule['severity']
                    if severity_val in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
                        custom_rules.append(custom_rule)
                        self.stats.increment('rules_successfully_converted')
                        logging.debug(f"Rule '{custom_rule['id']}' of severity '{severity_val}' converted and added.")
                    else:
                        self.stats.increment('rules_parsed_but_skipped_low_priority')
                elif custom_rule is None:
                    if rule_ir.operator == 'rx':
                        if rule_ir.pattern == '.*':
                            self.stats.increment('rules_skipped_generic_pattern')
                        else:
                            self.stats.increment('rules_skipped_no_targets')
                    else:
                        self.stats.increment('rules_skipped_non_rx_operator')
            if not custom_rules:
                if filename.lower().startswith("nasxi"):
                    logging.debug(f"Skipping file {filename} - no valid Nasxi rules to save.")
                else:
                    logging.info(f"Skipping file {filename} - no valid rules to save.")
                continue
            output_file = os.path.join(self.config.output_dir, "rules", f"{filename.replace('.conf', '')}.json")
            try:
                with open(output_file, 'w') as f:
                    json.dump(custom_rules, f, indent=2)
                logging.info(f"Saved {len(custom_rules)} rules from {filename} to {output_file}")
                aggregated_rules.extend(custom_rules)
            except IOError as e:
                logging.error(f"Error writing to {output_file}: {e}")
        return aggregated_rules

    def extract_nasxi_rules(self, rule_text: str, filename: str) -> List[ModSecurityRuleIR]:
        rules_ir = []
        for line in rule_text.splitlines():
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            if line.startswith("MainRule"):
                # Use regex to parse MainRule lines
                import re
                match = re.match(r'^MainRule\s+"([^"]+)"\s+"([^"]+)"\s+"([^"]+)"\s+"([^"]+)"\s+id:(\d+);', line)
                if match:
                    pattern_str = match.group(1)
                    msg = match.group(2)
                    variables_str = match.group(3)
                    s_value = match.group(4)
                    rule_id = match.group(5)
                    
                    # Remove operator prefix from pattern if present
                    clean_pattern = pattern_str.split(":", 1)[1] if (pattern_str.startswith("rx:") or pattern_str.startswith("str:")) else pattern_str
                    # Clean message
                    description = msg.split("msg:", 1)[-1].strip() if "msg:" in msg else msg
                    # Determine severity based on s_value content
                    if "4" in s_value:
                        severity = "CRITICAL"
                    elif "8" in s_value:
                        severity = "HIGH"
                    else:
                        severity = "MEDIUM"
                    actions = {'severity': severity, 'action': 'alert', 'msg': description}
                    # Process variables if available (remove mz: prefix)
                    variables = variables_str.split('|') if variables_str.startswith("mz:") else []
                    
                    rule_ir = ModSecurityRuleIR(
                        rule_id=rule_id,
                        phase=2,
                        variables=variables,
                        operator="nasxi",
                        pattern=clean_pattern,
                        actions=actions,
                        original_actions_str=line,
                        filename=filename
                    )
                    rules_ir.append(rule_ir)
                continue
            # ...existing fallback parsing (e.g. pipe-separated format)...
            parts = line.split('|')
            if len(parts) >= 3:
                rule_id = parts[0].strip()
                pattern = parts[1].strip()
                severity_val = parts[2].strip().upper()
                actions = {'severity': severity_val, 'action': 'alert', 'msg': 'Converted nasxi rule.'}
                rule_ir = ModSecurityRuleIR(
                    rule_id=rule_id,
                    phase=2,
                    variables=[],
                    operator='nasxi',
                    pattern=pattern,
                    actions=actions,
                    original_actions_str=line,
                    filename=filename
                )
                rules_ir.append(rule_ir)
        return rules_ir

    def process_base_rules(self) -> List[Dict[str, Any]]:
        base_rules = []
        if self.config.base_rules and self.config.base_rules.get("sources"):
            for source in self.config.base_rules["sources"]:
                try:
                    self.logger.info(f"Fetching base rules from source: {source['name']}")
                    content = self.http_client.get(source["url"])
                    try:
                        parsed = json.loads(content)
                        if isinstance(parsed, list):
                            base_rules.extend(parsed)
                        else:
                            base_rules.append(parsed)
                        self.logger.info(f"Successfully fetched base rules from {source['name']}")
                    except json.JSONDecodeError:
                        self.logger.error(f"Base rules from {source['name']} are not valid JSON.")
                except FetchError as e:
                    self.logger.error(f"Error fetching base rules from {source['name']}: {e}")
        return base_rules

    def run(self):
        aggregated_converted = self.write_rules(self.fetch_and_process_rules())
        base_rules = self.process_base_rules()
        merged_rules = aggregated_converted + base_rules
        output_file = os.path.join(self.config.output_dir, "rules", "rules.json")
        try:
            with open(output_file, 'w') as f:
                json.dump(merged_rules, f, indent=2)
            self.logger.info(f"Successfully saved all aggregated rules to {output_file}")
        except Exception as e:
            self.logger.error(f"Error writing aggregated rules to {output_file}: {e}")
        self.stats.report()

class RuleWriter:
    def __init__(self, output_dir: str):
        self.output_dir = os.path.join(output_dir, "rules")  # Save rules into "rules" folder
        self.logger = logging.getLogger(__name__)

    def write_rules(self, rules: List[Dict[str, Any]], filename: str) -> None:
        output_file = os.path.join(self.output_dir, filename)
        try:
            os.makedirs(os.path.dirname(output_file), exist_ok=True)
            with open(output_file, 'w') as f:
                json.dump(rules, f, indent=2)
        except IOError as e:
            self.logger.error(f"Failed to write rules to {output_file}: {e}")
            raise

class Statistics:
    def __init__(self):
        self.stats: Dict[str, int] = {
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
        self.logger = logging.getLogger(__name__)  # Add logger

    def increment(self, key: str) -> None:
        self.stats[key] += 1

    def report(self) -> None:
        self.logger.info("--- Rule Conversion Statistics ---")
        for key, value in self.stats.items():
            self.logger.info(f"{key}: {value}")
        self.logger.info("--- End Statistics ---")

class RuleAggregator:
    def __init__(self, config: Config, http_client: HttpClient, 
                 rule_processor: RuleProcessor, rule_writer: RuleWriter):
        self.config = config
        self.http_client = http_client
        self.rule_processor = rule_processor
        self.rule_writer = rule_writer
        self.stats = Statistics()
        self.logger = logging.getLogger(__name__)

    # New write_rules method to fix missing attribute error
    def write_rules(self, rules_with_filenames: List[tuple]) -> List[Dict[str, Any]]:
        aggregated_converted = []
        for filename, rules_ir in rules_with_filenames:
            custom_rules = []
            for rule_ir in rules_ir:
                custom_rule = self.rule_processor.process_rule(rule_ir)
                if custom_rule:
                    custom_rules.append(custom_rule)
                    self.stats.increment('rules_successfully_converted')
                else:
                    self.stats.increment('rules_skipped_non_rx_operator')
            if custom_rules:
                # Use RuleWriter to write individual files (ignoring nasxi rules if needed)
                if not filename.lower().startswith("nasxi"):
                    try:
                        out_filename = f"{filename.replace('.conf','')}.json"
                        self.rule_writer.write_rules(custom_rules, out_filename)
                    except IOError as e:
                        self.logger.error(f"Failed to write rules to {out_filename}: {e}")
                aggregated_converted.extend(custom_rules)
            else:
                if filename.lower().startswith("nasxi"):
                    self.logger.debug(f"Skipping file {filename} - no valid Nasxi rules to save.")
                else:
                    self.logger.info(f"Skipping file {filename} - no valid rules to save.")
        return aggregated_converted

    def fetch_and_process_rules(self) -> List[tuple]:
        all_rules_with_filenames = []

        # --- New block for rule sources defined in config.owasp_rules ---
        if self.config.owasp_rules and self.config.owasp_rules.get("sources"):
            for source in self.config.owasp_rules["sources"]:
                try:
                    self.logger.info(f"Fetching rules from source: {source['name']}")
                    file_content = self.http_client.get(source["url"])
                    pseudo_filename = f"{source['name']}.conf"
                    rules_ir = self.extract_rules(file_content, pseudo_filename)
                    all_rules_with_filenames.append((pseudo_filename, rules_ir))
                except FetchError as e:
                    self.logger.error(f"Error fetching rules from {source['name']}: {e}")
        # Fallback: if no OWASP rules were loaded and a valid repo_url is provided, fetch using the GitHub API.
        if not all_rules_with_filenames and self.config.repo_url != "default_repo_url":
            try:
                self.logger.info("Fallback: Fetching OWASP rules using GitHub API.")
                api_url = f"https://api.github.com/repos/coreruleset/coreruleset/contents/rules"
                response = self.http_client.get(api_url)
                files = json.loads(response)
                for file in files:
                    if not file['name'].endswith('.conf'):
                        continue
                    time.sleep(0.5)
                    file_content = self.http_client.get(file["download_url"])
                    self.logger.info(f"Processing rule file: {file['name']}")
                    rules_ir = self.extract_rules(file_content, file['name'])
                    all_rules_with_filenames.append((file['name'], rules_ir))
            except FetchError as e:
                self.logger.error(f"Fallback Error fetching OWASP rules: {e}")

        # New block for nasxi rules
        if self.config.nasxi_rules and self.config.nasxi_rules.get("sources"):
            for source in self.config.nasxi_rules["sources"]:
                try:
                    self.logger.info(f"Fetching nasxi rules from source: {source['name']}")
                    file_content = self.http_client.get(source["url"])
                    pseudo_filename = f"{source['name']}.nasxi"
                    rules_ir = self.extract_nasxi_rules(file_content, pseudo_filename)
                    all_rules_with_filenames.append((pseudo_filename, rules_ir))
                except FetchError as e:
                    self.logger.error(f"Error fetching nasxi rules from {source['name']}: {e}")
        else:
            # ...existing fallback logic...
            pass

        return all_rules_with_filenames

    def extract_rules(self, rule_text: str, filename: str) -> List[ModSecurityRuleIR]:
        rules_ir = []

        # Compile regular expressions once
        rule_pattern_re = re.compile(
            r'SecRule\s+([\s\S]+?)"([^"]+)"\s*([\s\S]+?)(?=SecRule|SecAction|SecDefaultAction|SecRuleRemoveTarget|SecRuleUpdateTargetById|SecMarker|^\s*#|$)')
        id_pattern_re = re.compile(r'id:(\d+)')
        operator_pattern_re = re.compile(r'@([a-zA-Z]+)\s*(.*)')
        action_pattern_re = re.compile(r'([a-zA-Z_]+):[\'"]?([^\'"]*)[\'"]?')

        # Preprocess patterns mapping
        def preprocess_operator(operator, operator_arg):
            try:
                if operator == 'lt':
                    value = int(operator_arg)
                    return f'@rx ^[0-{value - 1}]$'
                elif operator == 'rx':
                    return f'@rx {self.rule_processor.preprocess_pattern(operator_arg)}'[3:].strip()
                elif operator == 'pm':
                    return f'@rx {"|".join(re.escape(x.strip()) for x in operator_arg.split(","))}'
                elif operator == 'streq':
                    return f'@rx ^{re.escape(operator_arg)}$'
                elif operator == 'contains':
                    return f'@rx {re.escape(operator_arg)}'
                elif operator == 'beginsWith':
                    return f'@rx ^{re.escape(operator_arg)}'
                elif operator == 'endsWith':
                    return f'@rx ^{re.escape(operator_arg)}$'
                elif operator == 'eq':
                    return f'@rx ^{re.escape(operator_arg)}$'
                elif operator == 'ge':
                    return f'@rx ^[{operator_arg}-9]$'
                elif operator == 'le':
                    return f'@rx ^[0-{operator_arg}]$'
                else:
                    self.stats.increment('rules_skipped_non_rx_operator')
                    return None
            except ValueError:
                logging.warning(f"Invalid @lt operator in rule {rule_id}, using safe fallback.")
                return '@rx .*'
        
        for match in rule_pattern_re.finditer(rule_text):
            try:
                variables_str, pattern, actions_str = match.groups()
                
                # Extract rule ID
                id_match = id_pattern_re.search(actions_str)
                if id_match:
                    rule_id = id_match.group(1)
                else:
                    continue

                # Process operator and argument
                operator_match = operator_pattern_re.match(pattern)
                if operator_match:
                    operator, operator_arg = operator_match.groups()
                    operator_arg = operator_arg.strip()
                else:
                    operator, operator_arg = 'rx', pattern

                preprocessed_operator_arg = preprocess_operator(operator, operator_arg)
                if preprocessed_operator_arg is None:
                    logging.debug(f"Skipping unsupported operator '{operator}' in rule {rule_id}, File: {filename}.")
                    continue
                
                # Validate regex pattern
                regex_pattern_to_validate = preprocessed_operator_arg[3:].strip()
                try:
                    re.compile(regex_pattern_to_validate)
                except re.error as e:
                    logging.warning(f"Invalid regex pattern in rule {rule_id}: {regex_pattern_to_validate}. Error: {e}. Using safe fallback.")
                    preprocessed_operator_arg = '@rx .*'
                    self.stats.increment('rules_skipped_invalid_regex')
                
                variables_list = [v.strip() for v in variables_str.split(',')]

                actions = {m.group(1): m.group(2) for m in action_pattern_re.finditer(actions_str)}

                rule_ir = ModSecurityRuleIR(
                    rule_id=rule_id,
                    phase=int(actions.get('phase', 2)),
                    variables=variables_list,
                    operator=operator,
                    pattern=preprocessed_operator_arg,
                    actions=actions,
                    original_actions_str=actions_str,
                    filename=filename
                )
                
                rules_ir.append(rule_ir)
            except Exception as e:
                logging.error(f"Error parsing rule in {filename}: {e}. Raw rule content: {match.group(0)}")
                self.stats.increment('rules_parse_errors')

        return rules_ir

    def extract_nasxi_rules(self, rule_text: str, filename: str) -> List[ModSecurityRuleIR]:
        # Precompile the regular expression pattern to avoid recompiling in every iteration
        main_rule_re = re.compile(r'^MainRule\s+"([^"]+)"\s+"([^"]+)"\s+"([^"]+)"\s+"([^"]+)"\s+id:(\d+);')
        
        rules_ir = []
        for line in rule_text.splitlines():
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            
            if line.startswith("MainRule"):
                match = main_rule_re.match(line)
                if match:
                    pattern_str, msg, variables_str, s_value, rule_id = match.groups()

                    clean_pattern = pattern_str.split(":", 1)[1] if ':' in pattern_str else pattern_str
                    description = msg.split("msg:", 1)[-1].strip() if "msg:" in msg else msg

                    severity = "CRITICAL" if "4" in s_value else "HIGH" if "8" in s_value else "MEDIUM"
                    actions = {'severity': severity, 'action': 'alert', 'msg': description}

                    variables = variables_str.split('|') if variables_str.startswith("mz:") else []

                    rule_ir = ModSecurityRuleIR(
                        rule_id=rule_id,
                        phase=2,
                        variables=variables,
                        operator="nasxi",
                        pattern=clean_pattern,
                        actions=actions,
                        original_actions_str=line,
                        filename=filename
                    )
                    rules_ir.append(rule_ir)
                continue
            
            # Fallback for existing pipe-separated format
            parts = line.split('|')
            if len(parts) >= 3:
                rule_id = parts[0].strip()
                pattern = parts[1].strip()
                severity_val = parts[2].strip().upper()
                actions = {'severity': severity_val, 'action': 'alert', 'msg': 'Converted nasxi rule.'}
                
                rule_ir = ModSecurityRuleIR(
                    rule_id=rule_id,
                    phase=2,
                    variables=[],
                    operator='nasxi',
                    pattern=pattern,
                    actions=actions,
                    original_actions_str=line,
                    filename=filename
                )
                rules_ir.append(rule_ir)

        return rules_ir

    def process_base_rules(self) -> List[Dict[str, Any]]:
        base_rules = []
        if self.config.base_rules and self.config.base_rules.get("sources"):
            for source in self.config.base_rules["sources"]:
                try:
                    self.logger.info(f"Fetching base rules from source: {source['name']}")
                    content = self.http_client.get(source["url"])
                    try:
                        parsed = json.loads(content)
                        if isinstance(parsed, list):
                            base_rules.extend(parsed)
                        else:
                            base_rules.append(parsed)
                        self.logger.info(f"Successfully fetched base rules from {source['name']}")
                    except json.JSONDecodeError:
                        self.logger.error(f"Base rules from {source['name']} are not valid JSON.")
                except FetchError as e:
                    self.logger.error(f"Error fetching base rules from {source['name']}: {e}")
        return base_rules

    def run(self):
        aggregated_converted = self.write_rules(self.fetch_and_process_rules())
        base_rules = self.process_base_rules()
        merged_rules = aggregated_converted + base_rules
        output_file = os.path.join(self.config.output_dir, "rules", "rules.json")
        try:
            with open(output_file, 'w') as f:
                json.dump(merged_rules, f, indent=2)
            self.logger.info(f"Successfully saved all aggregated rules to {output_file}")
        except Exception as e:
            self.logger.error(f"Error writing aggregated rules to {output_file}: {e}")
        self.stats.report()

def main():
    # Setup structured logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    logger = logging.getLogger(__name__)

    try:
        config = Config.from_yaml('config.yaml')
        if not config.repo_url:
            raise ConfigurationError("repo_url is missing in the configuration")
        http_client = HttpClient(config.request_timeout, config.max_retries)
        rule_processor = ModSecurityRuleProcessor(config)
        rule_writer = RuleWriter(config.output_dir)
        
        aggregator = RuleAggregator(config, http_client, rule_processor, rule_writer)
        aggregator.run()
    except Exception as e:
        logger.error(f"Application failed: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()

