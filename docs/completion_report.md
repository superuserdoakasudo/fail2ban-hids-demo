# Fail2ban Host-Based Intrusion Detection System (HIDS) Demonstration
## Completion Report

**Author:** Student ID: 22332371  
**Date:** April 9, 2025

## 1. Project Overview

This project demonstrates the implementation of a Host-Based Intrusion Detection System (HIDS) using Fail2ban, a lightweight intrusion prevention framework. The system is designed to:

- Monitor system logs for suspicious activity
- Detect potential intrusion attempts
- Automatically block malicious IP addresses
- Generate comprehensive reports and statistics

The demonstration focuses primarily on SSH attack detection, which is one of the most common attack vectors for internet-facing servers. The project includes tools for simulating attacks, monitoring Fail2ban's response, and analyzing the effectiveness of the intrusion detection system.

This implementation serves as an educational tool for understanding HIDS principles and Fail2ban's capabilities, suitable for security portfolio demonstrations and academic purposes.

## 2. Implementation Details

### Architecture

The project implements a comprehensive HIDS solution with the following architecture:

1. **Detection Layer**: Fail2ban monitors authentication logs for suspicious activity
2. **Prevention Layer**: Automatic IP banning through iptables firewall rules
3. **Testing Framework**: Python-based attack simulation tools
4. **Monitoring & Analysis**: Real-time statistics and reporting

### Key Features

- **Customized Fail2ban Configuration**: Optimized for demonstration and testing
- **SSH Attack Simulation**: Configurable tool to test intrusion detection capabilities
- **Real-time Monitoring**: Log analysis with statistical reporting
- **Visualization**: ASCII-based charting of attack patterns
- **Data Export**: JSON and CSV export for further analysis

### Technical Stack

- **Programming Language**: Python 3
- **HIDS Framework**: Fail2ban
- **Firewall Technology**: iptables
- **Data Formats**: JSON, CSV
- **Version Control**: Git

## 3. Components Summary

### SSH Attack Simulator (`test-scripts/ssh_attack_simulator.py`)

This Python script simulates SSH login attempts to test Fail2ban's detection capabilities:

- Configurable number of login attempts
- Adjustable delay between attempts
- Random or specified username/password combinations
- Comprehensive logging of attack simulation activities
- Paramiko library for SSH connection handling

Key parameters include:
- `--host`: Target host IP address (default: 127.0.0.1)
- `--port`: SSH port number (default: 22)
- `--attempts`: Number of login attempts (default: 5)
- `--delay`: Delay between attempts in seconds (default: 1.0)
- `--random-creds`: Use random credentials for each attempt

### Fail2ban Monitor (`monitoring/fail2ban_monitor.py`)

This monitoring tool provides real-time analysis of Fail2ban's response to attacks:

- Real-time log monitoring
- Statistical analysis of ban events
- Identification of attack patterns
- Hourly distribution visualization
- Data export functionality for further analysis

The monitor tracks:
- Total bans and unbans
- Unique IP addresses
- Ban frequency (bans per hour)
- Attack detection rate
- Most common banned IPs
- Most active jails

### Fail2ban Configuration (`fail2ban-configs/jail.local`)

The custom Fail2ban configuration is optimized for demonstration purposes:

- Shorter ban and find times for quicker demonstration
- Lower retry thresholds to trigger bans more easily
- Multiple SSH jail configurations (normal and aggressive)
- Support for both IPv4 and IPv6
- Detailed comments explaining each configuration option

Key settings include:
- Ban time: 300 seconds (5 minutes)
- Find time: 60 seconds (1 minute)
- Maximum retries: 3
- Aggressive mode (optional): 2 retries, 1800 seconds ban time

### Documentation

- **README.md**: Setup instructions and project overview
- **This Completion Report**: Comprehensive project documentation

## 4. Testing Instructions

### Prerequisites

1. Ensure Fail2ban is installed:
   ```bash
   # On Debian/Ubuntu
   sudo apt-get install fail2ban

   # On RHEL/CentOS
   sudo yum install fail2ban
   ```

2. Create a Python virtual environment and install dependencies:
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   pip install -r requirements.txt
   ```

3. Copy the Fail2ban configuration:
   ```bash
   sudo cp fail2ban-configs/jail.local /etc/fail2ban/jail.local
   sudo systemctl restart fail2ban
   ```

### Running the Demonstration

1. Start the monitoring script in one terminal:
   ```bash
   python monitoring/fail2ban_monitor.py
   ```

2. In a separate terminal, run the attack simulator:
   ```bash
   python test-scripts/ssh_attack_simulator.py --attempts 10 --delay 0.5
   ```

3. Observe the monitoring output to see banned IPs and statistics.

### Interpreting Results

The monitoring tool provides several key metrics:
- **Total Bans**: Number of IP addresses that have been banned
- **Unique IPs Banned**: Number of distinct IP addresses that triggered bans
- **Attack Detection Rate**: Percentage of detected attacks that resulted in bans
- **Ban Frequency**: Rate of bans per hour
- **Top Banned IPs**: IPs with the most ban events
- **Most Active Jails**: Fail2ban jails that triggered the most bans

Results are automatically exported to the `results/` directory for further analysis.

## 5. Security Considerations

### Testing Safety

- **Controlled Environment**: This demonstration should only be run in a controlled environment, preferably a virtual machine or isolated network.
- **Local Testing**: Default configuration targets localhost (127.0.0.1) to prevent accidental attacks on external systems.
- **Authorization**: Never use these scripts against systems you don't own or have explicit permission to test.

### Production Considerations

If adapting this demonstration for production use, consider these modifications:

- **Increase Ban Times**: Production systems should use longer ban times (hours or days)
- **Persistent Bans**: Implement persistent ban storage to survive service restarts
- **Email Notifications**: Configure email alerts for ban events
- **External IP Blocklists**: Integrate with known malicious IP databases
- **Log Rotation**: Ensure proper log rotation to prevent disk space issues

### Ethical Usage

This project is designed for educational purposes only. Users should:
- Obtain proper authorization before testing on any system
- Follow responsible disclosure practices if vulnerabilities are discovered
- Respect privacy and data protection regulations

## 6. Future Enhancements

### Potential Improvements

1. **Web Interface**:
   - Develop a web dashboard for monitoring and visualization
   - Provide user-friendly interface for ban management

2. **Extended Protection**:
   - Add configurations for web server protection (Apache, Nginx)
   - Implement protection for mail services, FTP, and other common services

3. **Machine Learning Integration**:
   - Implement anomaly detection for more sophisticated attack recognition
   - Develop predictive models for potential attack patterns

4. **Distributed Monitoring**:
   - Create a network of sensors for distributed environments
   - Implement centralized logging and correlation

5. **Advanced Reporting**:
   - Geographic IP mapping and visualization
   - Threat intelligence integration
   - Attack timeline reconstruction

### Academic Extensions

For academic portfolio enhancement, consider:
- Comparative analysis with other HIDS solutions
- Performance benchmarking under various attack scenarios
- Case studies of real-world attack patterns
- Formal security assessment methodology

## Conclusion

This Fail2ban HIDS demonstration provides a solid foundation for understanding intrusion detection principles and implementing basic protection against SSH brute force attacks. The combination of custom configuration, attack simulation, and real-time monitoring creates a comprehensive educational tool for security studies.

The project successfully demonstrates the core capabilities of a HIDS while providing flexibility for future expansion and integration with more advanced security frameworks.

