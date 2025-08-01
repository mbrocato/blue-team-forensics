import argparse
import xml.etree.ElementTree as ET
import os
import subprocess
import json
import markdown

def parse_event_log(log_file):
    """Parse Windows event log (EVTX XML export) for anomalies like unauthorized logins."""
    tree = ET.parse(log_file)
    root = tree.getroot()
    anomalies = []
    for event in root.findall('.//{*}Event'):
        event_id = event.findtext('.//{*}EventID')
        time_created = event.findtext('.//{*}TimeCreated/@SystemTime')
        if event_id == '4625':  # Failed login attempt
            user = event.findtext('.//{*}Data[@Name="TargetUserName"]')
            anomalies.append({
                'event_id': event_id,
                'time': time_created,
                'description': f"Failed login for user: {user}"
            })
        elif event_id == '4624':  # Successful login
            user = event.findtext('.//{*}Data[@Name="TargetUserName"]')
            if user not in ['SYSTEM', 'LOCAL SERVICE']:  # Flag non-system logins
                anomalies.append({
                    'event_id': event_id,
                    'time': time_created,
                    'description': f"Suspicious login for user: {user}"
                })
    return anomalies

def analyze_memory_dump(dump_file):
    """Analyze memory dump with Volatility via subprocess (assumes Volatility installed)."""
    try:
        # Extract processes
        proc_output = subprocess.check_output(['vol.py', '-f', dump_file, 'pslist'], text=True)
        # Extract network connections (simplified; parse output)
        net_output = subprocess.check_output(['vol.py', '-f', dump_file, 'netscan'], text=True)
        return {
            'processes': proc_output.splitlines()[:10],  # First 10 for brevity
            'networks': net_output.splitlines()[:10]
        }
    except subprocess.CalledProcessError as e:
        return {"error": str(e)}

def generate_report(forensics_data, output_file='forensics_report.md'):
    """Generate Markdown report."""
    with open(output_file, 'w') as f:
        f.write("# Blue Team Forensics Report\n\n")
        f.write("## Event Log Anomalies\n")
        for anomaly in forensics_data.get('anomalies', []):
            f.write(f"- {anomaly['description']} at {anomaly['time']}\n")
        f.write("\n## Memory Dump Analysis\n")
        if 'error' in forensics_data.get('memory', {}):
            f.write(f"Error: {forensics_data['memory']['error']}\n")
        else:
            f.write("### Processes\n")
            for proc in forensics_data['memory'].get('processes', []):
                f.write(f"- {proc}\n")
            f.write("\n### Network Connections\n")
            for net in forensics_data['memory'].get('networks', []):
                f.write(f"- {net}\n")

    print(f"Report generated: {output_file}")

def main():
    parser = argparse.ArgumentParser(description="Blue Team Forensic Toolkit")
    parser.add_argument('--log', type=str, help="Path to event log XML file")
    parser.add_argument('--memory', type=str, help="Path to memory dump file")
    parser.add_argument('--report', action='store_true', help="Generate Markdown report")
    
    args = parser.parse_args()
    
    forensics = {}
    
    if args.log:
        forensics['anomalies'] = parse_event_log(args.log)
    
    if args.memory:
        forensics['memory'] = analyze_memory_dump(args.memory)
    
    if args.report:
        generate_report(forensics)
    else:
        print(json.dumps(forensics, indent=4))

if __name__ == "__main__":
    main()
