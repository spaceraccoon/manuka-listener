import hashlib

def extract_email_header(headers, name):
    for header in headers:
        if header['name'] == name:
            return header['value']