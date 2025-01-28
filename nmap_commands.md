# Comprehensive Nmap Automation Script Commands

## Basic Scanning

### Single Host Scans
```bash
# Quick SYN scan of common ports
python NmapScanner.py -t 192.168.1.1 -p 1-1024 -s syn

# Full port scan
python NmapScanner.py -t 192.168.1.1 -p 1-65535 -s syn

# UDP service scan
python NmapScanner.py -t 192.168.1.1 -p 53,161,123 -s udp
```

### Network Range Scans
```bash
# Scan entire subnet
python NmapScanner.py -t 192.168.1.0/24 -p 80,443 -s syn

# Scan multiple ports on subnet
python NmapScanner.py -t 10.0.0.0/16 -p 22,80,443,3389 -s syn
```

## Advanced Scanning

### Comprehensive Analysis
```bash
# Full system analysis
python NmapScanner.py -t 192.168.1.1 -p 1-65535 -s comprehensive

# Service version detection
python NmapScanner.py -t 192.168.1.1 -p 1-1024 -s comprehensive --timing 4
```

### Vulnerability Scanning
```bash
# Common port vulnerability scan
python NmapScanner.py -t 192.168.1.1 -p 1-1024 -s vulnerability

# Web service vulnerability scan
python NmapScanner.py -t 192.168.1.1 -p 80,443,8080 -s vulnerability
```

## Service-Specific Scans

### Web Services
```bash
# Standard web ports
python NmapScanner.py -t 192.168.1.1 -p 80,443,8080,8443 -s syn

# Alternative web ports
python NmapScanner.py -t 192.168.1.1 -p 8000-8999 -s comprehensive
```

### Database Services
```bash
# Common database ports
python NmapScanner.py -t 192.168.1.1 -p 3306,5432,1521,1433 -s syn

# MongoDB specific
python NmapScanner.py -t 192.168.1.1 -p 27017-27019 -s comprehensive
```

### Mail Services
```bash
# Standard mail ports
python NmapScanner.py -t 192.168.1.1 -p 25,110,143,465,587,993,995 -s syn
```

## Output Management

### JSON Output
```bash
# Basic scan with JSON output
python NmapScanner.py -t 192.168.1.1 -p 1-1024 -s syn -o scan_results -f json

# Subnet scan with JSON results
python NmapScanner.py -t 192.168.1.0/24 -p 80,443 -s syn -o network_map -f json
```

### CSV Output
```bash
# Service scan with CSV output
python NmapScanner.py -t 192.168.1.1 -p 1-1024 -s comprehensive -o services -f csv

# Vulnerability scan results in CSV
python NmapScanner.py -t 192.168.1.1 -p 1-1024 -s vulnerability -o vulns -f csv
```

## Performance Optimized

### Timing Templates
```bash
# Slow and stealthy
python NmapScanner.py -t 192.168.1.1 -p 1-1024 -s syn --timing 0

# Aggressive scan
python NmapScanner.py -t 192.168.1.1 -p 1-1024 -s syn --timing 4
```

### Resource Usage
```bash
# Light scan
python NmapScanner.py -t 192.168.1.1 -p 1-100 -s syn --timing 2

# Intensive scan
python NmapScanner.py -t 192.168.1.1 -p 1-65535 -s comprehensive --timing 4
```

## Special Use Cases

### IoT Device Scanning
```bash
# Common IoT ports
python NmapScanner.py -t 192.168.1.1 -p 80,443,1883,8883,5683 -s comprehensive

# IoT subnet scan
python NmapScanner.py -t 192.168.1.0/24 -p 80,443,1883,8883 -s syn
```

### VoIP System Scanning
```bash
# SIP service scan
python NmapScanner.py -t 192.168.1.1 -p 5060,5061 -s comprehensive

# Full VoIP infrastructure
python NmapScanner.py -t 192.168.1.0/24 -p 5060-5070 -s comprehensive
```

## Batch Operations

### Multiple Target Scanning
```bash
# Scan multiple hosts
cat targets.txt | xargs -I {} python NmapScanner.py -t {} -p 80,443 -s syn

# Network ranges
for subnet in "192.168.1.0/24" "10.0.0.0/24"; do
    python NmapScanner.py -t $subnet -p 22,80,443 -s syn -o "${subnet/\//_}" -f json
done
```

### Automated Reporting
```bash
# Daily security scan
python NmapScanner.py -t 192.168.1.0/24 -p 1-1024 -s vulnerability -o "scan_$(date +%Y%m%d)" -f json

# Weekly comprehensive audit
python NmapScanner.py -t 192.168.1.0/24 -p 1-65535 -s comprehensive -o "audit_$(date +%Y%m%d)" -f csv
```

## Best Practices

1. Always start with basic scans before moving to more intensive ones
2. Use appropriate timing templates based on network conditions
3. Save scan results for comparison and documentation
4. Use CIDR notation for efficient network range scanning
5. Consider the target network's capacity when selecting scan options
6. Regular vulnerability scans should be scheduled during low-traffic periods
