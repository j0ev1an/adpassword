'''
Copyright (c) 2023 j0ev1an

All rights reserved.

This file is part of the Windows AD Tool and is released under the "MIT License Agreement".
Please see the LICENSE file that should have been included as part of this package.

Link: https://github.com/j0ev1an/adpassword

Python Version:
/usr/bin/python3

Dependencies:
pip3 install pkcs7 pycryptodome
'''

import os, sys, getpass, hashlib, binascii, argparse

from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Util.Padding import pad
from pkcs7 import PKCS7Encoder



if len(sys.argv) == 1 or str(sys.argv[1]) == "-h":
    print("Interactive:")
    print("[+] Usage: python3 {} <host (or) user>".format(sys.argv[0]))
    print("[!] Info: if password is empty it asks for password in hex format")
    print("[*] eg: python3 {} host".format(sys.argv[0]))
    print("[*] eg: python3 {} user".format(sys.argv[0]))
    print()
    print("Command-Line:")
    print("[+] Usage: python3 {} -d <fqdn> -hn <hostname> -p <password>".format(sys.argv[0]))
    print("[+] Usage: python3 {} -d <fqdn> -un <username> -ph <passwordhex>".format(sys.argv[0]))
    print("[!] Info: if password or passwordhex parameter is not given it asks for password and if password is empty again it asks for passwordhex")
    print("[*] eg: python3 {} -d contoso.com -hn myhost -p Myhost123".format(sys.argv[0]))
    print("[*] eg: python3 {} -d contoso.com -hn myhost -ph 4d79686f7374313233".format(sys.argv[0]))
    print("[*] eg: python3 {} -d contoso.com -un myuser -p Myuser123".format(sys.argv[0]))
    print("[*] eg: python3 {} -d contoso.com -un myuser -ph 4d7975736572313233".format(sys.argv[0]))
    print()
    sys.exit(-1)



salt_type = ""



if len(sys.argv) < 3:
    domain_name = input("Enter FQDN\t\t: ")

    # Set Salt for AES Encryption - Host (or) User
    password_salt = ""

    if str(sys.argv[1]) == "host":
        host_name = input("Enter Hostname\t\t: ")
        host_password_salt = domain_name.upper() + "host" + host_name.lower() + "." + domain_name.lower()
        password_salt = host_password_salt
        salt_type = "host"
    elif str(sys.argv[1]) == "user":
        user_name = input("Enter Username\t\t: ")
        user_password_salt = domain_name.upper() + user_name
        password_salt = user_password_salt
        salt_type = "user"

    if len(password_salt) < 1:
        print()
        print("[-] Enter Hostname (or) Username")
        print()
        sys.exit(-1)

    # Get Password
    password = getpass.getpass(prompt="Enter Password\t\t: ").encode("utf-8")
    password_hex = ""

    if len(password) < 1:
        password_hex = getpass.getpass(prompt="Enter Password (hex)\t: ")
        password = binascii.unhexlify(password_hex)
    else:
        password_hex = binascii.hexlify(password).decode("utf8")

    if len(password_hex) < 1:
        print()
        print("[-] Enter Password (or) Password Hex")
        print()
        sys.exit(-1)



if len(sys.argv) > 3:
    parser = argparse.ArgumentParser()
    parser.add_argument('--domain', '-d', type=str, action='store', dest='domainname', default='')
    parser.add_argument('--hostname', '-hn', type=str, action='store', dest='hostname', default='')
    parser.add_argument('--username', '-un', type=str, action='store', dest='username', default='')
    parser.add_argument('--password', '-p', type=str, action='store', dest='password', default='')
    parser.add_argument('--passwordhex', '-ph', type=str, action='store', dest='passwordhex', default='')
    args = parser.parse_args()

    domain_name = args.domainname

    # Set Salt for AES Encryption - Host (or) User
    password_salt = ""

    if len(args.hostname) > 1:
        host_name = args.hostname
        host_password_salt = domain_name.upper() + "host" + host_name.lower() + "." + domain_name.lower()
        password_salt = host_password_salt
        salt_type = "host"
    elif len(args.username) > 1:
        user_name = args.username
        user_password_salt = domain_name.upper() + user_name
        password_salt = user_password_salt
        salt_type = "user"

    if len(password_salt) < 1:
        print()
        print("[-] Enter Hostname (or) Username")
        print()
        sys.exit(-1)

    # Get Password
    password_hex = ""

    if len(args.password) < 1 and len(args.passwordhex) > 1:
        password_hex = args.passwordhex
        password = binascii.unhexlify(password_hex)

    if len(args.password) > 1 and len(args.passwordhex) < 1:
        password = (args.password).encode("utf-8")
        password_hex = binascii.hexlify(password).decode("utf8")

    if len(args.password) < 1 and len(args.passwordhex) < 1:
        password = getpass.getpass(prompt="Enter Password\t\t: ").encode("utf-8")
        if len(password) < 1:
            password_hex = getpass.getpass(prompt="Enter Password (hex)\t: ")
            password = binascii.unhexlify(password_hex)
        else:
            password_hex = binascii.hexlify(password).decode("utf8")

    if len(password_hex) < 1:
        print()
        print("[-] Enter Password (or) Password Hex")
        print()
        sys.exit(-1)



print()
print("Salt (" + str(salt_type) + ")\t\t: " + password_salt)
if len(password_hex) < 1:
    print("Password\t\t: " + password.decode("utf8"))
    print("Password (hex)\t\t: " + password_hex)
else:
    if password.isascii():
        print("Password\t\t: " + password.decode("utf8"))
    print("Password (hex)\t\t: " + password_hex)

print()



# Calculate NTLM Hash
if len(password_hex) < 1:
    ntlm_hash = hashlib.new("md4", password.decode("utf8").strip().encode("utf-16le")).digest()
else:
    if password.isascii():
        ntlm_hash = hashlib.new("md4", password.decode("utf8").strip().encode("utf-16le")).digest()
    else:
        ntlm_hash = hashlib.new("md4", password).digest()
ntlm_hash_value = binascii.hexlify(ntlm_hash)



# Calculate AES Encryption Key
aes128_key = PBKDF2(password, password_salt.encode("utf-8"), 16, 4096)
aes256_key = PBKDF2(password, password_salt.encode("utf-8"), 32, 4096)
aes128_value = binascii.hexlify(aes128_key)
aes256_value = binascii.hexlify(aes256_key)
pbkdf2_aes128_key = aes128_value.decode("utf8")
pbkdf2_aes256_key = aes256_value.decode("utf8")



# Set AES Variables
encoder = PKCS7Encoder()
iv = "\x00" * 16
aes128_constant = b"\x6B\x65\x72\x62\x65\x72\x6F\x73\x7B\x9B\x5B\x2B\x93\x13\x2B\x93"
aes256_constant = b"\x6B\x65\x72\x62\x65\x72\x6F\x73\x7B\x9B\x5B\x2B\x93\x13\x2B\x93\x5C\x9B\xDC\xDA\xD9\x5C\x98\x99\xC4\xCA\xE4\xDE\xE6\xD6\xCA\xE4"



# Calculate Final AES128 Key
aes128_cipher = AES.new(aes128_key, AES.MODE_CBC, iv.encode("utf-8"))
cipher128_key = aes128_cipher.encrypt(pad(aes128_constant, AES.block_size))[:16]
cipher128_value = binascii.hexlify(cipher128_key)



# Calculate Final AES256 Key
aes256_cipher_01 = AES.new(aes256_key, AES.MODE_CBC, iv.encode("utf-8"))
aes256_cipher_02 = AES.new(aes256_key, AES.MODE_CBC, iv.encode("utf-8"))
cipher256_key_01 = aes256_cipher_01.encrypt(pad(aes256_constant, AES.block_size))[:32]
cipher256_key_02 = aes256_cipher_02.encrypt(pad(cipher256_key_01, len(cipher256_key_01)))[:32]



cipher256_value_01 = binascii.hexlify(cipher256_key_01)
cipher256_value_02 = binascii.hexlify(cipher256_key_02)
cipher256_value = cipher256_value_01[:32] + cipher256_value_02[:32]



# Print Password Keys
print("NTLM\t\t\t: " + ntlm_hash_value.decode("utf8"))
if password.isascii():
    print("AES128\t\t\t: " + cipher128_value.decode("utf8"))
    print("AES256\t\t\t: " + cipher256_value.decode("utf8"))
else:
    print("AES Keys\t\t: Failed (Password contains Non-ASCII characters)")
print()


