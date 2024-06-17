# Script for control easy-rsa certificates date expiration.

The script checks all certificates in a particular directory, reads the Not After attribute. 
If there are less than the specified number of days left until this date, it generates a message.

## Requirements
PyOpenSSL module require
```
pip install pyopenssl
```

## Command line argument
```
-c --config <path to configuration file>
```
If -c argument is not set, by default script open configuration file
from ../conf/config.ini


## Config file settings
file mast be located in .conf directory and have name config.ini
```
[options]
path=/etc/openvpn/easy-rsa/keys:/tmp/example
days=5
older_days=-14
cert_ext=.crt
alert_type=console/email
[mail]
email=my@domain.com
smtp=mail.domain.com
port=25
sender=checker@domain.com
```
#### Parameter description

- **days** : How many days before the certificate expires to send a warning message
- **older_days** : How many days after the expiration date of the certificate to send a notice
