# dump ph

this scripts implements a pretty ugly way to remotely dump entries from a server,
that does not support better ways.

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