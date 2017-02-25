#!/usr/bin/python

import json
import re
import sys
import urlparse
import subprocess
import datetime


def check_certificate(url):
    uri = urlparse.urlparse(url)
    host = '{uri.hostname}'.format(uri=uri)
    port = '{uri.port}'.format(uri=uri)
    if port == 'None':
        if '{uri.scheme}'.format(uri=uri) == 'https':
            port = 443
        else:
            port = 80
    command = "openssl s_client -showcerts -servername " + host + " -connect " + host + ":" + str(port) \
              + " < /dev/null | openssl x509 -inform pem -noout -text"
    proc = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    result = proc.stdout.read()
    if not result or "unable to load certificate" in result:
        return False
    cert = {
        "subject": {
            "name": "",
            "organisation": "",
            "organisation_unit": ""
        },
        "issuer": {
            "name": "",
            "organisation": "",
            "organisation_unit": ""
        },
        "validity": {
            "from": "",
            "to": ""
        },
        "return_code": False
    }
    subject_pattern = re.compile(r"Subject: (.*)$", re.MULTILINE)
    subject_match = subject_pattern.search(result)
    if subject_match:
        subject = subject_match.group(1)
        cert["subject"]["name"] = get_name(subject)
        cert["subject"]["organisation"] = get_organisation(subject)
        cert["subject"]["organisation_unit"] = get_organisation_unit(subject)
    issuer_pattern = re.compile(r"Issuer: (.*)$", re.MULTILINE)
    issuer_match = issuer_pattern.search(result)
    if issuer_match:
        issuer = issuer_match.group(1)
        cert["issuer"]["name"] = get_name(issuer)
        cert["issuer"]["organisation"] = get_organisation(issuer)
        cert["issuer"]["organisation_unit"] = get_organisation_unit(issuer)
    validity_pattern = re.compile(r"Validity\n\s*Not Before: (.*)\n\s*Not After : (.*)$", re.MULTILINE)
    validity_match = validity_pattern.search(result)
    if validity_match:
        cert["validity"]["from"] = parse_date(validity_match.group(1))
        cert["validity"]["to"] = parse_date(validity_match.group(2))

    command = "openssl s_client -verify_return_error -servername " + host + " -connect "\
              + host + ":" + str(port) + " < /dev/null"
    proc = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    result = proc.stdout.read()
    verify_pattern = re.compile(r"Verify return code: (\d+ \(.*\))$", re.MULTILINE)
    verify_match = verify_pattern.search(result)
    if verify_match:
        cert["return_code"] = verify_match.group(1)
    return cert


def parse_date(string):
    return datetime.datetime.strptime(string, '%b %d %H:%M:%S %Y %Z').isoformat()


def get_name(line):
    return find("CN", line)


def get_organisation(line):
    return find("O", line)


def get_organisation_unit(line):
    return find("OU", line)


def find(prefix, line):
    pattern = re.compile(r"" + prefix + "=(.*?)(, [A-Z]+=|$)")
    match = pattern.search(line)
    if match:
        return match.group(1)
    pass


def format_result(cert):
    if not cert:
        return {
            "result": "SUSPICIOUS",
            "info": None
        }

    result = "CLEAN"
    if cert["return_code"] != "0 (ok)":
        result = "MALICIOUS"

    return {
        "result": result,
        "info": {
            "certificate": cert
        }
    }


if __name__ == "__main__":
    if len(sys.argv) == 3:
        prefix = sys.argv[1]
        url = sys.argv[2]
        result = check_certificate(url)
        print '{}: {}'.format(prefix, json.dumps(format_result(result)))
    else:
        print "prefix, url or content missing"
