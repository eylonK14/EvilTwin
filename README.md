# Evil Twin

An Implementation of the Evil Twin Attack and a Defense Mechanism

## Table of Contents

- [Educational Use Only](#educational-use-only)
- [Project Overview](#project-overview)
  - [What is an Evil Twin Attack?](#what-is-an-evil-twin-attack)
  - [Defense Mechanism](#defense-mechanism)
- [Project Structure](#project-structure)
  - [File Descriptions](#file-descriptions)
- [System Requirements](#system-requirements)
  - [Recommended Platform: DragonOS](#recommended-platform-dragonos)
  - [Hardware Requirements](#hardware-requirements)
  - [Software Dependencies](#software-dependencies)
- [Installation & Setup](#installation--setup)
- [How to Run](#how-to-run)
  - [Running the Evil Twin Attack](#running-the-evil-twin-attack)
  - [Running the Defense System](#running-the-defense-system)
- [Configuration Options](#configuration-options)
- [Project Demonstration](#project-demonstration)
- [Legal and Ethical Considerations](#legal-and-ethical-considerations)
- [Contributing](#contributing)
- [License](#license)
- [Authors and Acknowledgments](#authors-and-acknowledgments)

## Educational Use Only

**WARNING: This project is for educational and research purposes only. Using this tool for unauthorized network access, capturing credentials, or any malicious activities is illegal and unethical. The authors are not responsible for any misuse of this software. Only use this on networks you own or have explicit permission to test.**

## Project Overview

This project demonstrates the Evil Twin attack, a type of WiFi security attack where an attacker creates a fake access point (AP) that mimics a legitimate wireless network to capture user credentials and sensitive information. The project also includes a defense mechanism to detect and mitigate such attacks.

### What is an Evil Twin Attack?

An Evil Twin attack involves:
1. **Network Reconnaissance**: Scanning for available WiFi networks and their clients
2. **Deauthentication Attack**: Forcing legitimate clients to disconnect from the real AP
3. **Fake Access Point**: Creating a malicious AP with the same SSID as the legitimate network
4. **Captive Portal**: Presenting a fake login page to capture user credentials
5. **Credential Harvesting**: Storing captured passwords for analysis

### Defense Mechanism

The project includes a defense module that:
- Detects deauthentication floods (indicating a potential attack)
- Identifies fake access points broadcasting the same SSID
- Automatically mitigates attacks by disrupting the fake AP
- Provides real-time monitoring and alerts

## Project Structure

```
EvilTwin/
├── README.md                          # This file
├── requirements.txt                   # Python dependencies
├── .gitignore                         # Git ignore file
├── evil_twin.py                       # Main attack script
├── defense.py                         # Defense mechanism
├── set_up_monitor.sh                  # Monitor mode setup script
credentials log
└── evil_twin_framework/              # Core framework modules
    ├── network.py                    # Network scanning and monitoring
    ├── data.py                       # Data display and formatting
    ├── dauth.py                      # Deauthentication attack module
    ├── fake_ap.py                    # Fake access point creation
    └── captive_portal.py             # Web-based credential capture portal
```

### File Descriptions

#### Core Files
- **`evil_twin.py`**: Main entry point for the attack. Orchestrates network scanning, target selection, fake AP creation, deauth attacks, and credential capture.
- **`defense.py`**: Standalone defense module that monitors for Evil Twin attacks and can automatically mitigate them.
- **`set_up_monitor.sh`**: Bash script to configure wireless interfaces in monitor mode.
- **`requirements.txt`**: Python package dependencies.

#### Framework Modules
- **`network.py`**: Handles WiFi network discovery, packet sniffing, channel hopping, and client tracking.
- **`data.py`**: Provides formatted display functions for networks, clients, and attack progress.
- **`dauth.py`**: Implements targeted deauthentication attacks to disconnect clients from legitimate APs.
- **`fake_ap.py`**: Creates and manages the fake access point using hostapd and dnsmasq.
- **`captive_portal.py`**: Web server that presents fake login pages and captures credentials.

## System Requirements

### Recommended Platform: DragonOS

We highly recommend using [DragonOS](https://github.com/DragonOS-Community/DragonOS) for this project. DragonOS is a penetration testing distribution based on Ubuntu, pre-installed with all necessary wireless tools and drivers. This will save you significant setup time and ensure compatibility with wireless hardware.

### Hardware Requirements
- **Two WiFi interfaces REQUIRED**:
  - Built-in WiFi adapter (for creating a fake AP)
  - External USB WiFi adapter with monitor mode support (for scanning and deauth attacks)
- **Recommended External Adapter**: EDUP AX3000 USB WiFi Adapter or similar
  - Supports monitor mode and packet injection
  - Excellent compatibility with Linux penetration testing tools
  - Dual-band (2.4GHz + 5GHz) support
- Root/sudo access required

**Note**: This project requires two separate WiFi interfaces to function properly. One interface cannot simultaneously run a fake AP and perform monitor mode operations.

### Software Dependencies
- Python 3.7+
- Linux operating system
- Wireless tools (iwconfig, hostapd, dnsmasq)

## Installation & Setup

### 1. Clone the Repository
```bash
git clone <repository-url>
cd EvilTwin
```

### 2. Install Python Dependencies
```bash
pip install -r requirements.txt
```

### 3. Install System Tools
```bash
# On Ubuntu/Debian-based systems
sudo apt-get update
sudo apt-get install hostapd dnsmasq wireless-tools aircrack-ng

# Ensure you have the necessary permissions
sudo setcap cap_net_raw,cap_net_admin+eip $(which python3)
```

### 4. Configure WiFi Interfaces
**IMPORTANT**: You need TWO WiFi interfaces for this project to work properly.

Check your available interfaces:
```bash
iwconfig
# You should see at least two WiFi interfaces (e.g., wlan0 and wlan1)
```

If you only have one built-in WiFi adapter, you MUST purchase an external USB WiFi adapter:
- **Recommended**: EDUP AX3000 USB WiFi Adapter

## How to Run

### Running the Evil Twin Attack

1. **Start the main script with root privileges**:
```bash
sudo python3 evil_twin.py
```

2. **Follow the interactive prompts**:
   - Select your wireless interface for monitoring (use your external USB adapter, e.g., wlan1)
   - Wait for network discovery (10 seconds)
   - Choose target network from the list
   - Select target client
   - Choose attack type ('e' for Evil Twin)

3. **Monitor the attack**:
   - Fake AP will be created on wlan0 (built-in adapter)
   - Deauth attacks will use your selected interface (external adapter)
   - Client should reconnect to your fake AP
   - Credentials will be captured and saved to `passwords.txt`

**Interface Usage**:
- **wlan0** (built-in): Hosts the fake access point
- **wlan1** (external USB): Performs scanning and deauth attacks

### Running the Defense System

```bash
# Example usage
sudo python3 -c "
from defense import defense
net = {'SSID': 'TargetNetwork', 'BSSID': '00:11:22:33:44:55'}
defense('wlan1', net, 'aa:bb:cc:dd:ee:ff')
"
```

### Stopping the Attack
- Press `Ctrl+C` or follow the on-screen prompts to stop
- The system will automatically clean up network configurations

## Configuration Options

### Defense Configuration
The defense module accepts several configuration parameters:
```python
defense(interface, net, user,
    time_window_seconds=2,          # Time window for deauth detection
    deauth_threshold=10,            # Deauth packets threshold
    auto_mitigate=True,             # Auto-mitigation enabled
    mitigation_duration_s=20,       # Duration of mitigation
    verbose=True                    # Enable detailed logging
)
```

## Project Demonstration

**Video Demonstration**: [Watch the full project demonstration](https://drive.google.com/drive/folders/1IlJ1ie6Ak1KdSkVGfpJMayGIm_ork0tv)

The demonstration video shows:
- Complete attack workflow
- Network scanning and target selection
- Fake AP creation and captive portal
- Credential capture process
- Defense mechanism in action

## Legal and Ethical Considerations

### IMPORTANT DISCLAIMERS

- **This tool is for educational and authorized testing purposes only**
- **Using this on networks without explicit permission is illegal**
- **Capturing others' credentials without consent is a criminal offense**
- **The authors assume no responsibility for misuse**

### Ethical Use Guidelines

**Acceptable Uses**:
- Learning about wireless security vulnerabilities
- Testing your own networks
- Authorized penetration testing with written permission
- Academic research in controlled environments
- Security awareness demonstrations

**Prohibited Uses**:
- Attacking networks without permission
- Stealing credentials or personal information
- Disrupting public or private networks
- Any malicious or illegal activities

## Contributing

Contributions are welcome! Please ensure all contributions maintain the educational focus and include appropriate warnings about responsible use.

## License

This project is provided for educational purposes. Users are responsible for complying with all applicable laws and regulations.

## Authors and Acknowledgments

This project was developed for educational purposes to demonstrate WiFi security vulnerabilities and defense mechanisms. We acknowledge the importance of responsible disclosure and ethical security research.

Authors:
- [Eylon Yaakov Katan](https://github.com/eylonk14)
- [Noam Leshem](https://github.com/noamleshem)
- [Lior Trachtman](https://github.com/TrachtmanLior)

---

**Remember: With great power comes great responsibility. Use this knowledge to defend, not to attack.**
