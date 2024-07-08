#!/usr/bin/env python3

# 
# from https://github.com/lclevy/firepwd/blob/master/firepwd.py
# wasn't working as expected after updates
# https://github.com/louisabraham/ffpass version was not parsing der encodings 
# correctly.
# this routines was written in order to overcome above.
# tested with firefox version 127.0.2 on ubuntu linux.
# -----------------------------------------------------
# important! if user has multiple profiles expect the unexpected :)) 

from base64 import b64decode
from hashlib import sha1, pbkdf2_hmac
import json
import sqlite3
from Crypto.Cipher import AES, DES3
from pyasn1.codec.der.decoder import decode as decodeDer
import sys
import os
import getpass

# asn1 octet
asn1octet = b"\xf8\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01"
# oidvalue 2a864886f70d0307: 1.2.840.113549.3.7 des-ede3-cbc
# oidvalue 60864801650304012a: 2.16.840.1.101.3.4.1.42 aes256-CBC
# oidvalue 2a864886f70d010c050103: 1.2.840.113549.1.12.5.1.3 pbeWithSha1AndTripleDES-CBC
# oidvalue 2a864886f70d0209 : 1.2.840.113549.2.9 hmacWithSHA256


# PKCS7 unpad
def unpad(padded_bytes):
    if(len(padded_bytes) == 16): return padded_bytes
    pad = int(padded_bytes[-1])
    return padded_bytes[0:len(padded_bytes)-pad]

# key to unlock login data is encrypted with aes_cbc 
def decrypt_aes(decoded_item, master_password, global_salt):
    entry_salt = decoded_item[0][1][0][1][0].asOctets()
    iteration_count = int(decoded_item[0][1][0][1][1])
    key_length = int(decoded_item[0][1][0][1][2])
    assert key_length == 32
    encoded_password = sha1(global_salt + master_password.encode('utf-8')).digest()
    key = pbkdf2_hmac(
        'sha256', encoded_password,
        entry_salt, iteration_count, dklen=key_length)

    init_vector = b'\x04\x0e' + decoded_item[0][1][1][1].asOctets()
    encrypted_value = decoded_item[1].asOctets()
    cipher = AES.new(key, AES.MODE_CBC, init_vector)
    return cipher.decrypt(encrypted_value)

# password check and obtain key
def get_db_key(filepath, masterpassword=""):
    keydb = filepath
    conn = sqlite3.connect(keydb)
    c = conn.cursor()
    c.execute("""
              SELECT item1, item2 FROM metadata
              WHERE id = 'password';
              """)
    row = next(c)
    globalSalt, item2 = row
    decoded_item2, _ = decodeDer(item2)
    plainText = decrypt_aes(decoded_item2, masterpassword, globalSalt)
    if plainText == b'password-check\x02\x02':
        print("[**] Password Check Ok")
    else:
        print("[ ! ] Password Check Fail !")
        return 
    c.execute("""
              SELECT a11, a102
              From nssPrivate
              Where a102 = ?
              """,(asn1octet,))
    row = next(c)
    a11, a102 = row
    decoded11 = decodeDer(a11)[0]
    loginKey = decrypt_aes(decoded11, masterpassword, globalSalt)
    conn.close()
    return loginKey[:24]

# decrypt username and password fields in login.json
def decrypt_usr_pwd(key, data):
    decoded, _ = decodeDer(b64decode(data))
    iv = decoded[1][1].asOctets()
    cipher = decoded[2].asOctets()
    des = DES3.new(key, DES3.MODE_CBC, iv)
    return unpad(des.decrypt(cipher)).decode()


def get_json_data(filePath):
    with open(filePath, 'r') as logins:
        jsonData = json.load(logins)
    return jsonData

# get login data from logins.json  
def export_logins(key, jsonData):
    loginData = []
    for data in jsonData['logins']:
        username = decrypt_usr_pwd(key,data["encryptedUsername"])
        passwd = decrypt_usr_pwd(key,data["encryptedPassword"])
        host = data["hostname"]
        loginData.append([host, username, passwd])
    return loginData

# search possible directories for key files 
def auto_search():
    search_for = ["key4.db","logins.json"]
    results = {}
    user = getpass.getuser()
    paths = []
    platform = sys.platform
    if platform == "linux":
        paths = [
            os.path.abspath(f"/home/{user}/snap/firefox/common/.mozilla/firefox"),
            os.path.abspath(f"/home/{user}/.mozilla/firefox")
        ]
    elif platform == 'darwin':
        paths = [
            "~/Library/Application Support/Firefox/Profiles"
        ]
    elif platform == 'win32':
        paths = [
            os.path.expandvars(r"%LOCALAPPDATA%\Mozilla\Firefox")
        ]
    else:
        print("[!] Platform is not recognized. Auto Search Fail")
        return None
    for path in paths:
        for root, dirs, files in os.walk(path):
            for name in files:
                if name == search_for[0]:
                    results['keydb'] = f"{os.path.join(root, name)}"
                elif name == search_for[1]:
                    results["json"] = f"{os.path.join(root, name)}"
    return results

# prints extracted keys to console...
def exractKeys(keydb, jsonFile, masterpassword = ""):
    loginKey = get_db_key(keydb, masterpassword)
    jd = get_json_data(jsonFile)
    exported = export_logins(loginKey, jd)
    for ex in exported:
        print(f"Host : {ex[0]}\nUsername : {ex[1]}\nPassword : {ex[2]}")
        print("-"*50)

def main(masterpassword=""):
    fileSearch = auto_search()
    if fileSearch != None:
        print("[**] Found key files Extracting login data")
        keydb = fileSearch['keydb']
        jsonFile = fileSearch['json']
        exractKeys(keydb, jsonFile, masterpassword)
    else:
        print("[**] Auto search failed. Trying local directory")
        keydb = os.path.join(os.path.curdir, "key4.db")
        jsonFile = os.path.join(os.path.curdir, "logins.json")
        if not os.path.exists(keydb) or not os.path.exists(jsonFile):
            print("[ ! ] ERROR : Keyfiles Not found please copy 'key4.db' and 'logins.json' files to current directory.")
            print("[ * ] Please visit 'https://support.mozilla.org/en-US/kb/where-are-my-logins-stored' page for instructions to find the local key files.")
        exractKeys(keydb, jsonFile)

pwd = getpass.getpass("Enter primary password(or empty if no password is set) :")
main(pwd)