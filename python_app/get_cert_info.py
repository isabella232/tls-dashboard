#!/usr/bin/env python3

import re
import os
import ssl
import json
import socket
import datetime

OUTPUT_TEMPLATE = """var run_date = '{run_date}';
var cert_info = {cert_info}"""


def parse_date(date_string):
    """
    Takes a date string and returns the nuumber of days between now and
    the future date
    """
    return datetime.datetime.strptime(date_string, "%b %d %X %Y %Z")


def camelcase_to_underscore(name):
    """
    Takes the SSL camelcase stuff and converts it to underscore
    Found on StackOverflow <http://stackoverflow.com/a/1176023/43363>
    """
    s1 = re.sub('(.)([A-Z][a-z]+)', r'\1_\2', name)
    return re.sub('([a-z0-9])([A-Z])', r'\1_\2', s1).lower()


def get_cert_parameters(hostname, timeout=5000, ssl_port=443):
    """
    Creates a connection to the host, and then reads the resulting peer
    certificate to extract the desired info
    """
    context = ssl.create_default_context()

    sock = socket.socket(socket.AF_INET)
    sock.settimeout(timeout)

    connection = context.wrap_socket(sock, server_hostname=hostname)
    connection.connect((hostname, ssl_port))

    certificate = connection.getpeercert()

    connection.close()

    cert_info = {
        "server": hostname,
        "subject": {},
        "issuer": {},
        "info": {}
    }

    for s in certificate.get('subject', None):
        subject = s[0]
        key = camelcase_to_underscore(subject[0])
        cert_info['subject'][key] = subject[1]

    for i in certificate.get('issuer', None):
        issuer = i[0]
        key = camelcase_to_underscore(issuer[0])
        cert_info['issuer'][key] = issuer[1]

    cert_info['info']['valid_from'] = parse_date(certificate['notAfter'])
    cert_info['info']['valid_to'] = parse_date(certificate['notBefore'])

    time_left = cert_info['info']['valid_from'] - datetime.datetime.now()

    cert_info['info']['days_left'] = time_left.days

    return cert_info


def json_default(obj):
    if isinstance(obj, datetime.datetime):
        return obj.isoformat()


def main():
    ROOT_PATH = os.path.dirname(os.path.abspath(__file__))

    with open(os.path.join(ROOT_PATH, 'config.json'), 'r') as f:
        config = json.loads(f.read())

    with open(os.path.join(ROOT_PATH, 'monitored_hosts.json'), 'r') as f:
        monitored_hosts = json.loads(f.read())

    cert_info = {}
    count = 1

    for host in monitored_hosts['hosts']:
        cert_info[count] = get_cert_parameters(host)
        count += 1

    with open(os.path.join(config['output_file']['path'],
                           config['output_file']['name']), 'w') as f:
        run_date = datetime.datetime.now().strftime('%a %b %d %Y')
        json_cert_info = json.dumps(cert_info, indent=4, default=json_default)

        f.write(OUTPUT_TEMPLATE.format(cert_info=json_cert_info,
                                       run_date=run_date))


if __name__ == '__main__':
    main()
