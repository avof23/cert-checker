# Script for control easy-rsa certificates date expiration.

The script checks all certificates in a particular directory, reads the Not After attribute. 
If there are less than the specified number of days left until this date, it generates a message.

## Requirements
PyOpenSSL module require
```
pip install pyopenssl
```

## Config file mode
file mast be located in .conf directory and have name config.ini
```
[options]
path=/etc/openvpn/easy-rsa:/tmp/example
days=5
cert_ext=.crt
alert_type=console/email
[mail]
email=my@domain.com
smtp=mail.domain.com
port=25
sender=checker@domain.com
```
