import re
import csv

def parse_asa_config(input_file):
    current_context = 'System'
    context_hostname = {'System': 'System'}
    objects = []
    current_object = None
    
    # Regex patterns
    context_pattern = re.compile(r'^context (\S+)')
    hostname_pattern = re.compile(r'^hostname (\S+)')
    object_pattern = re.compile(r'^object (network|service) (\S+)')
    network_group_pattern = re.compile(r'^object-group network (\S+)')
    service_group_pattern = re.compile(r'^object-group service (\S+)(?:\s+(tcp|udp|tcp-udp))?')
    
    # Value patterns
    value_patterns = {
        'network': [
            (r'^\s+host (\S+)', 'host', '{0}'),
            (r'^\s+subnet (\S+ \S+)', 'subnet', '{0}'),
            (r'^\s+range (\S+ \S+)', 'range', '{0}'),
            (r'^\s+fqdn(?:\s+v4|\s+v6)?\s+(\S+)', 'fqdn', '{0}')
        ],
        'service': [
            (r'^\s+service (tcp|udp) (.*)', lambda m: f"service-{m.group(1)}", '{1}'),
            (r'^\s+icmp-type (\S+)', 'icmp-type', '{0}')
        ]
    }

    with open(input_file, 'r') as f:
        for line_num, line in enumerate(f, 1):  # Start line numbering at 1
            stripped = line.strip()
            
            # Context/hostname handling
            if context_match := context_pattern.match(stripped):
                current_context = context_match.group(1)
                context_hostname[current_context] = current_context
                continue
                
            if host_match := hostname_pattern.match(stripped):
                context_hostname[current_context] = host_match.group(1)
                continue
                
            # Service group parsing
            if svc_grp_match := service_group_pattern.match(stripped):
                if current_object:
                    objects.append(current_object)
                proto = svc_grp_match.group(2) or 'mixed'
                current_object = {
                    'context': context_hostname.get(current_context, current_context),
                    'name': svc_grp_match.group(1),
                    'type': f'service-group-{proto}',
                    'value': [],
                    'description': '',
                    'reference': line_num  # Added line number capture
                }
                continue
                
            # Network group handling
            if net_grp_match := network_group_pattern.match(stripped):
                if current_object:
                    objects.append(current_object)
                current_object = {
                    'context': context_hostname.get(current_context, current_context),
                    'name': net_grp_match.group(1),
                    'type': 'network-group',
                    'value': [],
                    'description': '',
                    'reference': line_num  # Added line number capture
                }
                continue
                
            # Object detection
            if obj_match := object_pattern.match(stripped):
                if current_object:
                    objects.append(current_object)
                current_object = {
                    'context': context_hostname.get(current_context, current_context),
                    'name': obj_match.group(2),
                    'type': obj_match.group(1),
                    'value': '',
                    'description': '',
                    'reference': line_num  # Added line number capture
                }
                continue
                
            if current_object:
                # Service group port handling
                if current_object['type'].startswith('service-group'):
                    if port_match := re.match(r'^\s+port-object (eq|range) (\S+)(?:\s+(\S+))?', line):
                        if port_match.group(1) == 'eq':
                            current_object['value'].append(port_match.group(2))
                        elif port_match.group(1) == 'range':
                            current_object['value'].append(f"{port_match.group(2)}-{port_match.group(3)}")
                    continue
                
                # Network group member handling
                if current_object['type'] == 'network-group':
                    if member_match := re.match(r'^\s+network-object object (\S+)', line):
                        current_object['value'].append(member_match.group(1))
                    continue
                
                # Value parsing
                if line.startswith((' ', '\t')):
                    for pattern, obj_type, value_format in value_patterns.get(current_object['type'], []):
                        if match := re.match(pattern, line):
                            if callable(obj_type):
                                current_object['type'] = obj_type(match)
                            else:
                                current_object['type'] = obj_type
                            current_object['value'] = value_format.format(*match.groups())
                            break

                # Description handling
                if stripped.startswith('description '):
                    current_object['description'] = stripped[12:]

    if current_object:
        objects.append(current_object)
        
    return objects

def write_csv(output_file, objects):
    with open(output_file, 'w', newline='') as f:
        writer = csv.writer(f)
        # Added 'Reference' to header
        writer.writerow(['Context Name', 'Object Name', 'Object Type', 'Object Value', 'Object Description', 'Reference'])
        
        for obj in objects:
            value = '; '.join(obj['value']) if isinstance(obj['value'], list) else obj['value']
            # Added obj['reference'] to row
            writer.writerow([
                obj['context'],
                obj['name'],
                obj['type'],
                value,
                obj['description'],
                obj['reference']
            ])

if __name__ == '__main__':
    import sys
    if len(sys.argv) != 3:
        print("Usage: python asa_parser.py <input_file> <output_file>")
        sys.exit(1)
        
    objects = parse_asa_config(sys.argv[1])
    write_csv(sys.argv[2], objects)
    print(f"Processed {len(objects)} objects, output written to {sys.argv[2]}")
