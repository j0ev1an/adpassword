### AD Password -> NTLM, AES128, AES256
Convert Active Directory password to NTLM, AES128 and AES256

#### Key Features:
```
1. Converts from clear-text password
2. Converts from password hex (useful for machine account credentials)
3. Need not worry about case-sensitive issues on input values except clear-text password
```

#### Dependencies:
```
pip3 install pkcs7 pycryptodome
```

#### Python3 MD4 Support:
```
NTLM hash type MD4 is marked as legacy algorithm.

To check MD4 support in Python3:
python3 -c "import hashlib;print(hashlib.algorithms_available);"

Modify the file:
/etc/ssl/openssl.cnf
(or)
/etc/ssl/openssl.conf

...
[provider_sect]
default = default_sect
legacy = legacy_sect

[default_sect]
activate = 1

[legacy_sect]
activate = 1
...
```

#### Usage:
```
Interactive:
[+] Usage: python3 adpassword.py <host (or) user>
[!] Info: if password is empty it asks for password in hex format
[*] eg: python3 adpassword.py host
[*] eg: python3 adpassword.py user

Command-Line:
[+] Usage: python3 adpassword.py -d <fqdn> -hn <hostname> -p <password>
[+] Usage: python3 adpassword.py -d <fqdn> -un <username> -ph <passwordhex>
[!] Info: if password or passwordhex parameter is not given it asks for password and if password is empty again it asks for passwordhex
[*] eg: python3 adpassword.py -d contoso.com -hn myhost -p Myhost123
[*] eg: python3 adpassword.py -d contoso.com -hn myhost -ph 4d79686f7374313233
[*] eg: python3 adpassword.py -d contoso.com -un myuser -p Myuser123
[*] eg: python3 adpassword.py -d contoso.com -un myuser -ph 4d7975736572313233
```



#### Examples (Host - Interactive):
```
$ python3 adpassword.py host
Enter FQDN              : contoso.com
Enter Hostname          : myhost
Enter Password          :

Salt (host)             : CONTOSO.COMhostmyhost.contoso.com
Password                : Myhost123
Password (hex)          : 4d79686f7374313233

NTLM                    : 259a32585b02fcf5b19834bfa98f01b6
AES128                  : 169862de58ec5e81aea9b377ec438888
AES256                  : 4235a3e4a09f148f75ba9ce67f0d8c0bc46148b7a5dc3bdb22ef4e581e0afdb8



$ python3 adpassword.py host
Enter FQDN              : contoso.com
Enter Hostname          : myhost
Enter Password          :
Enter Password (hex)    :

Salt (host)             : CONTOSO.COMhostmyhost.contoso.com
Password                : Myhost123
Password (hex)          : 4d79686f7374313233

NTLM                    : 259a32585b02fcf5b19834bfa98f01b6
AES128                  : 169862de58ec5e81aea9b377ec438888
AES256                  : 4235a3e4a09f148f75ba9ce67f0d8c0bc46148b7a5dc3bdb22ef4e581e0afdb8



$ python3 adpassword.py host
Enter FQDN              : contoso.com
Enter Hostname          : mynewhost
Enter Password          :
Enter Password (hex)    :

Salt (host)             : CONTOSO.COMhostmynewhost.contoso.com
Password (hex)          : a5972c85b0526020b1287f07c55c4aefe1bd93aa312c61d39ab6afe21aaa09258b008171acb48a93575a63be10fbf6648868d50079ad6a90d4e815573292a676c32795b2b3b3d3344262c4e20517552412c28526d503fd4198e7c42bf491a75c1b9e48705312135b642f39c3514a937cc5af6e5a470047477c20460ae0b313d6e99b8717308d0c3c27a9060d8bdb58a57e9eb33cfd00317f9f644f40b7dd28bbe967b8d391b255b5ef63c6704c711b4220ee717e9025af984bdf092284c56f2493dcbbb78bdd3ae1242da12843e00f6c42b4590f5cbc46cb96004bd3b5889f313fe63418079489b8397b978f40b39ea2

NTLM                    : 55668625f78b702669e47fd3e406f492
AES Keys                : Failed (Password contains Non-ASCII characters)
```

#### Examples (Host - CommandLine):
```
$ python3 adpassword.py -d contoso.com -hn myhost
Enter Password          :

Salt (host)             : CONTOSO.COMhostmyhost.contoso.com
Password                : Myhost123
Password (hex)          : 4d79686f7374313233

NTLM                    : 259a32585b02fcf5b19834bfa98f01b6
AES128                  : 169862de58ec5e81aea9b377ec438888
AES256                  : 4235a3e4a09f148f75ba9ce67f0d8c0bc46148b7a5dc3bdb22ef4e581e0afdb8



$ python3 adpassword.py -d contoso.com -hn myhost
Enter Password          :
Enter Password (hex)    :

Salt (host)             : CONTOSO.COMhostmyhost.contoso.com
Password                : Myhost123
Password (hex)          : 4d79686f7374313233

NTLM                    : 259a32585b02fcf5b19834bfa98f01b6
AES128                  : 169862de58ec5e81aea9b377ec438888
AES256                  : 4235a3e4a09f148f75ba9ce67f0d8c0bc46148b7a5dc3bdb22ef4e581e0afdb8



$ python3 adpassword.py -d contoso.com -hn myhost -p Myhost123
Salt (host)             : CONTOSO.COMhostmyhost.contoso.com
Password                : Myhost123
Password (hex)          : 4d79686f7374313233

NTLM                    : 259a32585b02fcf5b19834bfa98f01b6
AES128                  : 169862de58ec5e81aea9b377ec438888
AES256                  : 4235a3e4a09f148f75ba9ce67f0d8c0bc46148b7a5dc3bdb22ef4e581e0afdb8



$ python3 adpassword.py -d contoso.com -hn myhost -ph 4d79686f7374313233
Salt (host)             : CONTOSO.COMhostmyhost.contoso.com
Password                : Myhost123
Password (hex)          : 4d79686f7374313233

NTLM                    : 259a32585b02fcf5b19834bfa98f01b6
AES128                  : 169862de58ec5e81aea9b377ec438888
AES256                  : 4235a3e4a09f148f75ba9ce67f0d8c0bc46148b7a5dc3bdb22ef4e581e0afdb8



$ python3 adpassword.py -d contoso.com -hn mynewhost -ph a5972c85b0526020b1287f07c55c4aefe1bd93aa312c61d39ab6afe21aaa09258b008171acb48a93575a63be10fbf6648868d50079ad6a90d4e815573292a676c32795b2b3b3d3344262c4e20517552412c28526d503fd4198e7c42bf491a75c1b9e48705312135b642f39c3514a937cc5af6e5a470047477c20460ae0b313d6e99b8717308d0c3c27a9060d8bdb58a57e9eb33cfd00317f9f644f40b7dd28bbe967b8d391b255b5ef63c6704c711b4220ee717e9025af984bdf092284c56f2493dcbbb78bdd3ae1242da12843e00f6c42b4590f5cbc46cb96004bd3b5889f313fe63418079489b8397b978f40b39ea2
Salt (host)             : CONTOSO.COMhostmynewhost.contoso.com
Password (hex)          : a5972c85b0526020b1287f07c55c4aefe1bd93aa312c61d39ab6afe21aaa09258b008171acb48a93575a63be10fbf6648868d50079ad6a90d4e815573292a676c32795b2b3b3d3344262c4e20517552412c28526d503fd4198e7c42bf491a75c1b9e48705312135b642f39c3514a937cc5af6e5a470047477c20460ae0b313d6e99b8717308d0c3c27a9060d8bdb58a57e9eb33cfd00317f9f644f40b7dd28bbe967b8d391b255b5ef63c6704c711b4220ee717e9025af984bdf092284c56f2493dcbbb78bdd3ae1242da12843e00f6c42b4590f5cbc46cb96004bd3b5889f313fe63418079489b8397b978f40b39ea2

NTLM                    : 55668625f78b702669e47fd3e406f492
AES Keys                : Failed (Password contains Non-ASCII characters)
```

#### Examples (User - Interactive):
```
$ python3 adpassword.py user
Enter FQDN              : contoso.com
Enter Username          : myuser
Enter Password          :

Salt (user)             : CONTOSO.COMmyuser
Password                : Myuser123
Password (hex)          : 4d7975736572313233

NTLM                    : 3c8499f8a17fb872e864edb2543be0e6
AES128                  : a3d030c03fcafecdf2bd3050039265a0
AES256                  : 7046df51477295129a7776fb32f6c424e04036111902559a053dc9e96639b3cd



$ python3 adpassword.py user
Enter FQDN              : contoso.com
Enter Username          : myuser
Enter Password          :
Enter Password (hex)    :

Salt (user)             : CONTOSO.COMmyuser
Password                : Myuser123
Password (hex)          : 4d7975736572313233

NTLM                    : 3c8499f8a17fb872e864edb2543be0e6
AES128                  : a3d030c03fcafecdf2bd3050039265a0
AES256                  : 7046df51477295129a7776fb32f6c424e04036111902559a053dc9e96639b3cd
```

#### Examples (User - CommandLine):
```
$ python3 adpassword.py -d contoso.com -un myuser
Enter Password          :

Salt (user)             : CONTOSO.COMmyuser
Password                : Myuser123
Password (hex)          : 4d7975736572313233

NTLM                    : 3c8499f8a17fb872e864edb2543be0e6
AES128                  : a3d030c03fcafecdf2bd3050039265a0
AES256                  : 7046df51477295129a7776fb32f6c424e04036111902559a053dc9e96639b3cd



$ python3 adpassword.py -d contoso.com -un myuser
Enter Password          :
Enter Password (hex)    :

Salt (user)             : CONTOSO.COMmyuser
Password                : Myuser123
Password (hex)          : 4d7975736572313233

NTLM                    : 3c8499f8a17fb872e864edb2543be0e6
AES128                  : a3d030c03fcafecdf2bd3050039265a0
AES256                  : 7046df51477295129a7776fb32f6c424e04036111902559a053dc9e96639b3cd



$ python3 adpassword.py -d contoso.com -un myuser -p Myuser123
Salt (user)             : CONTOSO.COMmyuser
Password                : Myuser123
Password (hex)          : 4d7975736572313233

NTLM                    : 3c8499f8a17fb872e864edb2543be0e6
AES128                  : a3d030c03fcafecdf2bd3050039265a0
AES256                  : 7046df51477295129a7776fb32f6c424e04036111902559a053dc9e96639b3cd



$ python3 adpassword.py -d contoso.com -un myuser -ph 4d7975736572313233
Salt (user)             : CONTOSO.COMmyuser
Password                : Myuser123
Password (hex)          : 4d7975736572313233

NTLM                    : 3c8499f8a17fb872e864edb2543be0e6
AES128                  : a3d030c03fcafecdf2bd3050039265a0
AES256                  : 7046df51477295129a7776fb32f6c424e04036111902559a053dc9e96639b3cd
```


#### References:
```
https://www.trustedsec.com/blog/generate-an-ntlm-hash-in-3-lines-of-python/
https://gist.github.com/Kevin-Robertson/9e0f8bfdbf4c1e694e6ff4197f0a4372
```
