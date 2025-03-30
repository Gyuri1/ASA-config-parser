



import re
import csv
from collections import defaultdict

def parse_acl_entries(input_file):
    current_context = 'System'
    context_hostname = 'System'
    acl_entries = []
    acl_name_map = defaultdict(list)
    
    # Regex patterns optimized for ASA syntax
    context_pattern = re.compile(r'^context\s+(\S+)')
    hostname_pattern = re.compile(r'^hostname\s+(\S+)')
    acl_pattern = re.compile(
        r'^access-list\s+(\S+)\s+extended\s+'
        r'(permit|deny)\s+'
        r'(?:object-group\s+)?(\S+)\s+'  # Protocol
        r'(?:object-group\s+|object\s+|host\s+)?(\S+)\s+'  # Source
        r'(?:object-group\s+|object\s+|host\s+)?(\S+)'  # Destination
        r'(?:\s+(?:eq|range|lt|gt|neq)\s+\S+)?'  # Port
        r'(?:\s+(log|log\sdisable|log\sinterval\s\d+))?'  # Log
    )
    remark_pattern = re.compile(r'^access-list\s+(\S+)\s+remark\s+(.*)')

    with open(input_file, 'r') as f:
        for line in f:
            line = line.strip()
            if not line:
                continue

            # Context detection
            if context_match := context_pattern.match(line):
                current_context = context_match.group(1)
                continue
                
            # Hostname detection
            if host_match := hostname_pattern.match(line):
                context_hostname = host_match.group(1)
                continue

            # Remark handling
            if remark_match := remark_pattern.match(line):
                acl_name = remark_match.group(1)
                acl_name_map[acl_name].append(remark_match.group(2))
                continue

            # ACL entry detection
            if acl_match := acl_pattern.match(line):
                entry = {
                    'context': context_hostname,
                    'name': acl_match.group(1),
                    'action': acl_match.group(2),
                    'type': acl_match.group(3),
                    'source': acl_match.group(4),
                    'destination': acl_match.group(5),
                    'log': acl_match.group(6) or 'no',
                    'remarks': '; '.join(acl_name_map.get(acl_match.group(1), []))
                }
                acl_entries.append(entry)
                if acl_match.group(1) in acl_name_map:
                    del acl_name_map[acl_match.group(1)]

    return acl_entries

def write_acl_csv(output_file, acl_entries):
    # Same as original
    with open(output_file, 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(['Context_name', 'name_of_Access_List', 'Action', 
                        'Type', 'Source', 'Destination', 'Log', 'Remark'])
        
        for entry in acl_entries:
            writer.writerow([
                entry['context'],
                entry['name'],
                entry['action'],
                entry['type'],
                entry['source'],
                entry['destination'],
                entry['log'],
                entry['remarks']
            ])

if __name__ == '__main__':
    import sys
    if len(sys.argv) != 3:
        print("Usage: python acl_parser.py <input_file> <output_file>")
        sys.exit(1)
        
    acl_data = parse_acl_entries(sys.argv[1])
    write_acl_csv(sys.argv[2], acl_data)
    print(f"Processed {len(acl_data)} ACL entries, output written to {sys.argv[2]}")
