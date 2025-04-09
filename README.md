## Project Setup Instructions

1. First, create a new repository on GitHub:
   - Go to https://github.com/new
   - Name it 'fail2ban-hids-demo'
   - Set it as Public
   - Do not initialize with README (we already have one)

2. Then, run these commands to push the code:
   ```bash
   git remote add origin https://github.com/YOUR_USERNAME/fail2ban-hids-demo.git
   git branch -M main
   git push -u origin main
   ```

## Development Setup

1. Create a Python virtual environment:
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

## Testing Prerequisites

1. Ensure Fail2ban is installed:
   ```bash
   # On Debian/Ubuntu
   sudo apt-get install fail2ban

   # On RHEL/CentOS
   sudo yum install fail2ban
   ```

2. Copy the Fail2ban configuration:
   ```bash
   sudo cp fail2ban-configs/jail.local /etc/fail2ban/jail.local
   sudo systemctl restart fail2ban
   ```

## Running Tests

1. Start the monitoring script:
   ```bash
   python monitoring/fail2ban_monitor.py
   ```

2. In a separate terminal, run the attack simulator:
   ```bash
   python test-scripts/ssh_attack_simulator.py
   ```

## Project Structure

- `test-scripts/`: Contains attack simulation scripts
- `fail2ban-configs/`: Fail2ban configuration files
- `monitoring/`: Scripts for monitoring and analyzing Fail2ban behavior
- `docs/`: Documentation and results
- `logs/`: Log files (created during execution)
- `results/`: Analysis results and reports (created during execution)

## Safety Notice

This project is for educational purposes only. All testing should be performed in a controlled environment, preferably a virtual machine. Never use these scripts against systems you don't own or have explicit permission to test.
