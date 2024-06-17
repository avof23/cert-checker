import os
import configparser
import smtplib
from datetime import datetime as dt
from datetime import timedelta

from OpenSSL import crypto

now = dt.now()
config = configparser.ConfigParser()

if os.path.exists('../conf/config.ini'):
    config.read('../conf/config.ini')
    work_path = config["options"]["path"].split(sep=":")
    days_before_expire = int(config["options"]["days"])
    days_older_cert = int(config["options"]["older_days"])
    cert_extension = config["options"]["cert_ext"]
    alert_type = config["options"]["alert_type"]
    email_receiver = config["mail"]["email"]
    smtp_server = config["mail"]["smtp"]
    port = int(config["mail"]["port"])
    email_sender = config["mail"]["sender"]
else:
    work_path = "."
    days_before_expire = 5
    days_older_cert = -14
    cert_extension = ".crt"
    alert_type = "console"


def check_cert(cert_path: str) -> tuple:
    # FILETYPE_ASN1
    with open(cert_path) as fcrt:
        cert = crypto.load_certificate(crypto.FILETYPE_PEM, fcrt.read())

    notafter = dt.strptime(cert.get_notAfter().decode('ascii'), '%Y%m%d%H%M%SZ')
    days_left = notafter - now

    if days_left <= timedelta(days=days_before_expire) and days_left > days_older_cert:
        return False, notafter
    return True, notafter


def send_email(cert_name: str, date_expiration: dt):
    alertmsg = (f'The Certificate {cert_name} Not after: {date_expiration},\n'
               f'left: {date_expiration - now}.\n'
               f'Pleace generate new certificate for user!')
    if alert_type == "email":
        message = (f"Subject: Openvpn certificate expiration Alert\n"
                   f"{alertmsg}")
        with smtplib.SMTP(smtp_server, port) as server:
            server.sendmail(email_sender, email_receiver, message)
    else:
        print(alertmsg)


def scaning_certs(certs_path: str) -> int:
    if not os.path.exists(certs_path):
        print(f'path to certificate is not exist {certs_path}')
        return 1
    with os.scandir(path=certs_path) as fileobject:
        for file in fileobject:
            if cert_extension in file.name:
                cert_status = check_cert(file.path)
                if not cert_status[0]:
                    send_email(file.name, cert_status[1])
            else:
                continue
    return 0


for path in work_path:
    print(f'Processing dir {path}')
    scaning_certs(path)
