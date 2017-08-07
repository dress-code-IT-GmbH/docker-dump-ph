# dump ph

this scripts implements a pretty ugly way to remotely dump some person entries from a server,
that does not support better ways.

# IMPORTANT WARNING: THIS IS NOT A BACKUP

this script might not get all entries! It will just get "almost all".

## Configuration and running

Configuration is done via config file. See dump.conf.example

CacertFile is for a file, concatenating PEM encoded certificates.
CacertPath needs to be a hashed directory (openssl c_rehash).

## Standard file locations for docker

/var/data/dump.conf - Config
/var/data/certificates.pem - CacertFile
/var/data/data.ldif - Output

## Usage:

```
optional arguments:
  -h, --help            show this help message and exit
  -c CONFIG, --conf CONFIG
                        test config file
  -d DUMP, --dump DUMP  selects the dump in case more than one dump is defined
                        in the config file
  -l, --log             write a ldap log to the file "ldap.log"
  -o OUTPUT, --output OUTPUT
                        output file
```