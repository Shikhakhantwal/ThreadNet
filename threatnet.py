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
                (r'sudo: (.+) : TTY=.+ ; PWD=.+ ; USER=root ; COMMAND=(.+)', 'MEDIUM', 'Sudo command execution', 'Audit privileged command usage.'),
                (r'failed login|login failed|authentication failure', 'HIGH', 'Failed login attempt explicitly detected', 'Check for unauthorized access attempts.'),
                (r'login successful|logged in', 'LOW', 'Successful authentication', 'Normal operation.')
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
            ],
            'windows_event': [
                (r'EventID: 4625', 'HIGH', 'Failed login attempt', 'Check for brute-force attacks on this account.'),
                (r'EventID: 4624', 'LOW', 'Successful login', 'Review if this login was expected at this time.'),
                (r'EventID: 4672', 'MEDIUM', 'Special privileges assigned', 'New logon has administrative rights. Monitor for unusual commands.'),
                (r'EventID: 4720', 'HIGH', 'User account created', 'Unauthorized account creation? Audit user management logs.'),
                (r'EventID: 1102', 'HIGH', 'Audit log cleared', 'Critical: Someone is trying to hide their tracks!')
            ],
            'generic_log': [
                (r'ERROR|CRITICAL|FATAL', 'ERROR', 'System Error detected', 'Check system health and dependency status.'),
                (r'WARNING|WARN', 'WARNING', 'System Warning detected', 'Monitor for potential issues.'),
                (r'INFO', 'INFO', 'System Information', 'Normal operation log.')
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
                    'timestamp': str(datetime.now().strftime("%Y-%m-%d %H:%M:%S")),
                    'log_line': 'N/A (Aggregate Anomaly)',
                    'type': 'ANOMALY',
                    'severity': 'HIGH',
                    'description': f'Statistical Anomaly: Spike in "{event_type}"',
                    'reasoning': f'Detected {count} occurrences, which is above the threshold of {threshold}. This volume indicates potential automated probing or misconfiguration.',
                    'advice': 'Investigate for automated attacks, credential stuffing, or script malfunctions.'
                })
        return anomalies

    def correlate_events(self, alerts):
        """Correlate multiple alerts to find complex attack patterns or ambiguities."""
        # Find brute force followed by success
        ips = {}
        for a in alerts:
            # Extract IP if present in log line or matches
            ip_match = re.search(r'(\d+\.\d+\.\d+\.\d+)', a['log_line'])
            if ip_match:
                ip = ip_match.group(1)
                if ip not in ips: ips[ip] = []
                ips[ip].append(a)
        
        correlated = []
        for ip, ip_alerts in ips.items():
            failed = [a for a in ip_alerts if 'Failed' in a['description']]
            success = [a for a in ip_alerts if 'Successful' in a['description'] or 'Accepted' in a['description']]
            sudo = [a for a in ip_alerts if 'Sudo' in a['description']]
            
            # Pattern 1: Brute force then success
            if failed and success:
                correlated.append({
                    'timestamp': str(datetime.now().strftime("%Y-%m-%d %H:%M:%S")),
                    'log_line': f"Correlation for source: {ip}",
                    'severity': 'CRITICAL',
                    'description': 'Ambiguous Activity: Brute-force followed by Success',
                    'reasoning': f"The source IP {ip} successfully logged in after {len(failed)} failed attempts. This has a high probability of being a successful brute-force attack.",
                    'advice': 'Lock account immediately and audit all activity from this source. Review user session logs for suspicious commands.'
                })
            
            # Pattern 2: Success then sudo
            if success and sudo:
                correlated.append({
                    'timestamp': str(datetime.now().strftime("%Y-%m-%d %H:%M:%S")),
                    'log_line': f"Correlation for source: {ip}",
                    'severity': 'MEDIUM',
                    'description': 'Elevated Activity: Login followed by Sudo',
                    'reasoning': f"User from {ip} performed a successful login and then executed privileged commands via sudo.",
                    'advice': 'Audit the sudo commands to ensure they align with the employee\'s role.'
                })

        # Pattern 3: Same user, multiple IPs (Conflicting Signals)
        user_ips = {}
        for a in alerts:
            if 'matches' in a and a['matches']:
                # The first group in login rules is usually the user
                if 'login' in a['description'].lower() or 'Accepted' in a['log_line']:
                    user = a['matches'][0]
                    ip_match = re.search(r'(\d+\.\d+\.\d+\.\d+)', a['log_line'])
                    if ip_match:
                        ip = ip_match.group(1)
                        if user not in user_ips: user_ips[user] = set()
                        user_ips[user].add(ip)

        for user, ips in user_ips.items():
            if len(ips) > 1:
                correlated.append({
                    'timestamp': str(datetime.now().strftime("%Y-%m-%d %H:%M:%S")),
                    'log_line': f"Conflict for user: {user}",
                    'severity': 'HIGH',
                    'description': 'Conflicting Signal: Multi-Source Login',
                    'reasoning': f"User '{user}' logged in from multiple distinct IP addresses ({', '.join(ips)}) in the same period. This could indicate credential sharing or compromised account.",
                    'advice': 'Contact user to verify activity and reset password if necessary.'
                })

        return correlated

    def scan_log(self, log_content, log_type='linux_auth'):
        alerts = []
        lines = log_content.splitlines()
        
        current_rules = self.rules.get(log_type, self.rules['generic_syslog'])
        # Also include generic log levels for broad visibility
        generic_rules = self.rules['generic_log']
        
        for line in lines:
            if not line.strip(): continue
            matched = False
            
            # Check specific security rules first
            for pattern, severity, desc, advice in current_rules:
                match = re.search(pattern, line, re.IGNORECASE)
                if match:
                    alert = {
                        'timestamp': str(datetime.now().strftime("%Y-%m-%d %H:%M:%S")),
                        'log_line': line.strip(),
                        'severity': severity,
                        'description': desc,
                        'reasoning': f"Security Policy Match: {desc}. Detected artifacts: {', '.join(match.groups()) if match.groups() else 'Generic pattern'}",
                        'advice': advice,
                        'matches': match.groups()
                    }
                    alerts.append(alert)
                    matched = True
                    break 
            
            # If no security rule matched, try generic level parsing
            if not matched:
                for pattern, severity, desc, advice in generic_rules:
                    if re.search(pattern, line, re.IGNORECASE):
                        alert = {
                            'timestamp': str(datetime.now().strftime("%Y-%m-%d %H:%M:%S")),
                            'log_line': line.strip(),
                            'severity': severity,
                            'description': desc,
                            'reasoning': f"Standard Level Detection: {severity}",
                            'advice': advice,
                            'matches': []
                        }
                        alerts.append(alert)
                        matched = True
                        break
                        
            # If completely unmatched, add as uncategorized so no log lines are lost
            if not matched:
                alerts.append({
                    'timestamp': str(datetime.now().strftime("%Y-%m-%d %H:%M:%S")),
                    'log_line': line.strip(),
                    'severity': 'LOW',
                    'description': 'Uncategorized Log Entry',
                    'reasoning': 'The log line did not match any known security signatures or levels.',
                    'advice': 'No immediate threat detected. Raw line ingested.',
                    'matches': []
                })
        
        # Add anomalies
        anomalies = self.detect_anomalies(alerts)
        alerts.extend(anomalies)
        
        # Add correlated alerts
        correlated = self.correlate_events(alerts)
        alerts.extend(correlated)
        
        # Sort by timestamp (approximate since we use current time for now)
        # In a real app we would parse the log's actual timestamp
        return alerts

    def export_json(self, alerts, filepath):
        with open(filepath, 'w') as f:
            json.dump(alerts, f, indent=4)

    def export_csv(self, alerts, filepath):
        if not alerts:
            return
        # Clean up alerts for CSV (remove matches dict/list)
        csv_alerts = []
        for a in alerts:
            ca = a.copy()
            if 'matches' in ca: del ca['matches']
            csv_alerts.append(ca)
            
        keys = csv_alerts[0].keys()
        with open(filepath, 'w', newline='') as f:
            dict_writer = csv.DictWriter(f, fieldnames=keys)
            dict_writer.writeheader()
            dict_writer.writerows(csv_alerts)