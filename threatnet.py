import re
import json
import csv
from datetime import datetime
from collections import Counter

class ThreatNetEngine:
    def __init__(self):
        # Rules: (Pattern, Severity, Description, Advice)
        self.rules = {
            'linux_auth': [
                (r'Failed password for invalid user (.+) from (\d+\.\d+\.\d+\.\d+)', 'HIGH', 'Brute force attempt on invalid user', 'Block IP address immediately.'),
                (r'Failed password for (.+) from (\d+\.\d+\.\d+\.\d+)', 'MEDIUM', 'Failed login attempt', 'Monitor IP for repeated failures.'),
                (r'Accepted password for (.+) from (\d+\.\d+\.\d+\.\d+)', 'LOW', 'Successful login', 'Normal behavior, verify if unexpected IP.'),
                (r'sudo: (.+) : TTY=.+ ; PWD=.+ ; USER=root ; COMMAND=(.+)', 'MEDIUM', 'Sudo command execution', 'Audit privileged command usage.')
            ],
            'web_server': [
                (r'\"GET /(.+) HTTP/.+\" 404', 'LOW', 'Resource not found', 'Normal web noise, scan for patterns.'),
                (r'\"GET /(.+)(\.env|config|wp-admin|phpmyadmin) HTTP/.+\" 404', 'HIGH', 'Sensitive path scanning', 'Block IP, check for more aggressive probes.'),
                (r'\"POST /login HTTP/.+\" 200', 'MEDIUM', 'Login attempt successful', 'Verify if user is authorized.'),
                (r'\"POST /login HTTP/.+\" 401', 'MEDIUM', 'Login attempt failed', 'Check for brute force.')
            ],
            'generic_syslog': [
                (r'kernel: (.+) : (.+)', 'LOW', 'Kernel message', 'Check hardware status.'),
                (r'sh: (.+) : error', 'MEDIUM', 'Shell error', 'Check for script failures or shell injection.')
            ]
        }

    def detect_anomalies(self, events):
        """Basic anomaly detection: check for spikes in event types."""
        threshold = 5  # Arbitrary threshold for "spike"
        event_types = [e['description'] for e in events]
        counts = Counter(event_types)
        
        anomalies = []
        for event_type, count in counts.items():
            if count > threshold:
                anomalies.append({
                    'timestamp': str(datetime.now()),
                    'log_line': 'N/A (Aggregate Anomaly)',
                    'type': 'ANOMALY',
                    'severity': 'HIGH',
                    'description': f'Spike in "{event_type}" detected ({count} occurrences)',
                    'advice': 'Investigate for automated attacks or system failures.'
                })
        return anomalies

    def scan_log(self, log_content, log_type='linux_auth'):
        alerts = []
        lines = log_content.splitlines()
        
        current_rules = self.rules.get(log_type, self.rules['generic_syslog'])
        
        for line in lines:
            for pattern, severity, desc, advice in current_rules:
                match = re.search(pattern, line)
                if match:
                    alert = {
                        'timestamp': str(datetime.now()),
                        'log_line': line.strip(),
                        'severity': severity,
                        'description': desc,
                        'advice': advice,
                        'matches': match.groups()
                    }
                    alerts.append(alert)
                    break # Match only first rule for a line for simplicity
        
        # Add anomalies
        anomalies = self.detect_anomalies(alerts)
        alerts.extend(anomalies)
        
        return alerts

    def export_json(self, alerts, filepath):
        with open(filepath, 'w') as f:
            json.dump(alerts, f, indent=4)

    def export_csv(self, alerts, filepath):
        if not alerts:
            return
        keys = alerts[0].keys()
        with open(filepath, 'w', newline='') as f:
            dict_writer = csv.DictWriter(f, fieldnames=keys)
            dict_writer.writeheader()
            dict_writer.writerows(alerts)