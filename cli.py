import argparse
import os
import sys
from threatnet import ThreatNetEngine

def main():
    parser = argparse.ArgumentParser(description="ThreatNet CLI - Scan logs for suspicious activity")
    parser.add_argument("file", help="Path to the log file to scan")
    parser.add_argument("--type", choices=['linux_auth', 'web_server', 'generic_syslog'], 
                        default='linux_auth', help="Type of log file (default: linux_auth)")
    parser.add_argument("--format", choices=['text', 'json', 'csv'], default='text', 
                        help="Output format (default: text)")
    parser.add_argument("--out", help="Output file path")

    args = parser.parse_args()

    if not os.path.exists(args.file):
        print(f"Error: File {args.file} not found.")
        sys.exit(1)

    engine = ThreatNetEngine()
    
    with open(args.file, 'r') as f:
        content = f.read()

    print(f"[*] Scanning {args.file} ({args.type})...")
    alerts = engine.scan_log(content, args.type)

    if not alerts:
        print("[+] No threats detected.")
        return

    print(f"[!] Detected {len(alerts)} suspicious incidents.")

    if args.format == 'text':
        for alert in alerts:
            print(f"[{alert['severity']}] {alert['description']}")
            if 'log_line' in alert and alert['log_line'] != 'N/A (Aggregate Anomaly)':
                print(f"  Line: {alert['log_line']}")
            print(f"  Advice: {alert['advice']}")
            print("-" * 40)
    elif args.format == 'json':
        import json
        output = json.dumps(alerts, indent=2)
        if args.out:
            with open(args.out, 'w') as f:
                f.write(output)
            print(f"[*] Exported to {args.out}")
        else:
            print(output)
    elif args.format == 'csv':
        if args.out:
            engine.export_csv(alerts, args.out)
            print(f"[*] Exported to {args.out}")
        else:
            print("Error: CSV format requires --out <filepath>")

if __name__ == "__main__":
    main()
