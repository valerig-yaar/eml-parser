import ipaddress
import email
import os
import re
import logging
import json
import magic
import argparse
import datetime
import tldextract
from email.header import decode_header
from email.utils import parsedate_to_datetime
from bs4 import BeautifulSoup
from io import BytesIO

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def extract_from(msg):
    """
    Extract the sender's email address from the email message.

    Args:
        msg (email.message.Message): The email message object.

    Returns:
        str: The sender's email address or None if extraction fails.
    """
    try:
        sender = msg.get("From")
        if sender:
            return re.search(r'<(.+?)>', sender).group(1) if '<' in sender else sender
    except Exception as e:
        logging.error(f"Failed to extract sender: {e}")
        return None

def extract_date(msg):
    """
    Extract the date from the email message.

    Args:
        msg (email.message.Message): The email message object.

    Returns:
        tuple: A tuple containing the date object and the timestamp, or (None, None) if extraction fails.
    """
    try:
        date_str = msg.get("Date")
        if date_str:
            date_obj = parsedate_to_datetime(date_str)
            return date_obj, date_obj.timestamp()
    except Exception as e:
        logging.error(f"Failed to extract date: {e}")
        return None, None

def extract_to(msg):
    """
    Extract the recipient email addresses from the email message.

    Args:
        msg (email.message.Message): The email message object.

    Returns:
        list: A list of recipient email addresses or an empty list if extraction fails.
    """
    try:
        recipients = msg.get_all("To", [])
        all_recipients = set()
        email_pattern = r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'
        for recipient in recipients:
            emails = re.findall(email_pattern, recipient)
            for email in emails:
                all_recipients.add(email.lower())
        return list(all_recipients)
    except Exception as e:
        logging.error(f"Failed to extract recipients: {e}")
        return []

def parse_email_headers(header):
    """
    Parse the email headers to extract IP addresses and domains.

    Args:
        header (str): The email header string.

    Returns:
        dict: A dictionary containing 'from_ips' and 'to_domains' lists.
    """
    from_value = header.split("from", 1)[1].split("by", 1)[0].replace('[', '').replace(']', '')
    by_value = header.split("by", 1)[1].split("with", 1)[0]

    # Extract IPs from "from" field
    ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
    from_ips = re.findall(ip_pattern, from_value) if from_value else []

    # Extract domains from "by" field, including "localhost"
    domain_pattern = r'([a-zA-Z0-9.-]+\.[a-zA-Z]{2,}|localhost)'
    by_domains = re.findall(domain_pattern, by_value) if by_value else []

    return {
        'from_ips': from_ips,
        'to_domains': by_domains
    }

def extract_sender_recipient(msg):
    """
    Extract the sender's IP address and recipient's domain from the email message.

    Args:
        msg (email.message.Message): The email message object.

    Returns:
        dict or list: A dictionary containing 'from_ips' and 'to_domains' lists, or a list of IP addresses.
    """
    try:
        received_headers = msg.get_all("Received", [])
        ip_pattern = r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b|(?:[a-fA-F0-9]{1,4}:){7}[a-fA-F0-9]{1,4}\b"
        all_ips = []
        for header in received_headers:
            if header.startswith("from"):
                return parse_email_headers(header)
            else:
                ip_matches = re.findall(ip_pattern, header)
            for ip in ip_matches:
                all_ips.append(ipaddress.ip_address(ip))
        return all_ips if all_ips else None
    except Exception as e:
        logging.error(f"Failed to extract IP addresses: {e}")
        return None

def extract_subject(msg):
    """
    Extract the subject from the email message.

    Args:
        msg (email.message.Message): The email message object.

    Returns:
        str: The subject of the email or None if extraction fails.
    """
    try:
        subject = msg.get("Subject")
        if subject:
            decoded_subject = decode_header(subject)[0]
            return decoded_subject[0].decode(decoded_subject[1]) if isinstance(decoded_subject[0], bytes) else decoded_subject[0]
    except Exception as e:
        logging.error(f"Failed to extract subject: {e}")
        return None

def extract_links_and_domains(part):
    """
    Extract links and domains from the email part.

    Args:
        part (email.message.Message): The email part object.

    Returns:
        list: A list of unique URLs found in the email part.
    """
    try:
        content_type = part.get_content_type()
    except Exception as e:
        logging.error(f"Failed to get content type: {e}")
        return []

    urls = []
    try:
        if content_type == "text/html":
            body = part.get_payload(decode=True).decode(errors="ignore")
            body = BeautifulSoup(body, 'html.parser')
            url_pattern = r'(https:\/\/www\.|http:\/\/www\.|https:\/\/|http:\/\/)?[a-zA-Z]{2,}(\.[a-zA-Z]{2,})(\.[a-zA-Z]{2,})?\/[a-zA-Z0-9]{2,}|((https:\/\/www\.|http:\/\/www\.|https:\/\/|http:\/\/)?[a-zA-Z]{2,}(\.[a-zA-Z]{2,})(\.[a-zA-Z]{2,})?)|(https:\/\/www\.|http:\/\/www\.|https:\/\/|http:\/\/)?[a-zA-Z0-9]{2,}\.[a-zA-Z0-9]{2,}\.[a-zA-Z0-9]{2,}(\.[a-zA-Z0-9]{2,})?'
            for tag in body.find_all(True):
                for attr in tag.attrs.values():
                    if isinstance(attr, str) and re.match(url_pattern, attr):
                        urls.append(attr)
        elif content_type == "text/plain":
            body = part.get_payload(decode=True).decode(errors="ignore")
            url_pattern = r'https?://[^\s"<>]+|www\.[^\s"<>]+'
            urls = re.findall(url_pattern, body)
    except Exception as e:
        logging.error(f"Failed to extract links and domains: {e}")
    return list(set(urls))

def search_urls(text):
    """
    Search for URLs in the given text.

    Args:
        text (str): The text to search for URLs.

    Returns:
        list: A list of URLs found in the text.
    """
    try:
        url_regex = r"https?://[^\s]+"
        return re.findall(url_regex, text)
    except Exception as e:
        logging.error(f"Failed to search URLs: {e}")
        return []

def extract_domains(urls):
    """
    Extract domains from the given list of URLs.

    Args:
        urls (list): A list of URLs.

    Returns:
        list: A list of unique domains extracted from the URLs.
    """
    domains = set()
    for url in urls:
        ext = tldextract.extract(url)
        domain = f"{ext.domain}.{ext.suffix}"
        domains.add(domain)
    return list(domains)

def extract_iocs_from_eml(file_path):
    """
    Extract Indicators of Compromise (IOCs) from an EML file.

    Args:
        file_path (str): The path to the EML file.

    Returns:
        dict: A dictionary containing extracted IOCs.
    """
    iocs = {
        "sender_email": None,
        "sender_ip": None,
        "recipient_emails": [],
        "recipient_dest": None,
        "subject": None,
        "links": [],
        "domains": [],
        "date": None,
        "timestamp": None
    }

    try:
        with open(file_path, "r", encoding="utf-8") as f:
            msg = email.message_from_file(f)
    except Exception as e:
        logging.error(f"Failed to open EML file: {e}")
        return iocs

    sender_recipient = extract_sender_recipient(msg)

    if isinstance(sender_recipient, dict):
        iocs['sender_ip'] = sender_recipient['from_ips'][0] if sender_recipient['from_ips'] else None
        iocs['recipient_dest'] = sender_recipient['to_domains'][0] if sender_recipient['to_domains'] else None
    else:
        iocs["sender_ip"] = sender_recipient[-1] if sender_recipient else None
        iocs["recipient_dest"] = sender_recipient[0] if sender_recipient else None

    iocs['sender_email'] = extract_from(msg)
    iocs["recipient_emails"] = extract_to(msg)
    iocs["subject"] = extract_subject(msg)
    iocs["date"], iocs["timestamp"] = extract_date(msg)
    if msg.is_multipart():
        for part in msg.walk():
            links = extract_links_and_domains(part)
            iocs["links"] = list(set(links + iocs["links"]))
    else:
        links = extract_links_and_domains(msg)
        iocs["links"] = list(set(links + iocs["links"]))

    iocs["domains"] = extract_domains(iocs["links"])

    return iocs

def process_eml_files(directory, recursive=False):
    """
    Process all EML files in the given directory and optionally in subdirectories.

    Args:
        directory (str): The directory containing EML files.
        recursive (bool): Whether to process files in subdirectories recursively.

    Returns:
        list: A list of dictionaries containing extracted IOCs for each EML file.
    """
    result = []
    for root, dirs, files in os.walk(directory):
        for filename in files:
            file_path = os.path.join(root, filename)
            if magic.from_file(file_path, mime=True) == 'message/rfc822':
                logging.info(f"Processing file: {filename}")
                iocs = extract_iocs_from_eml(file_path)
                result.append(iocs)
            else:
                logging.warning(f"Skipping non-EML file: {filename}")
        if not recursive:
            break
    return result

def open_eml(file_path=None, buffer=None):
    """
    Open an EML file from a file path or a buffer.

    Args:
        file_path (str): The path to the EML file or directory.
        buffer (BytesIO): The buffer containing the EML data.

    Returns:
        list: A list of email.message.Message objects.
    """
    messages = []
    try:
        if file_path:
            if os.path.isdir(file_path):
                for filename in os.listdir(file_path):
                    file_path = os.path.join(file_path, filename)
                    if magic.from_file(file_path, mime=True) == 'message/rfc822':
                        with open(file_path, "r", encoding="utf-8") as f:
                            msg = email.message_from_file(f)
                            messages.append(msg)
            elif os.path.isfile(file_path):
                if magic.from_file(file_path, mime=True) != 'message/rfc822':
                    raise ValueError('File is not a valid .eml file')
                with open(file_path, "r", encoding="utf-8") as f:
                    msg = email.message_from_file(f)
                    messages.append(msg)
            else:
                raise ValueError('Invalid file path')
        elif buffer:
            if magic.from_buffer(buffer.getvalue(), mime=True) != 'message/rfc822':
                raise ValueError('Buffer does not contain a valid .eml file')
            msg = email.message_from_bytes(buffer.getvalue())
            messages.append(msg)
        else:
            raise ValueError('Either file_path or buffer must be provided')
    except Exception as e:
        logging.error(f"Failed to open EML: {e}")
        raise
    return messages

class CustomJSONEncoder(json.JSONEncoder):
    """
    Custom JSON encoder to handle specific object types.
    """
    def default(self, obj):
        if isinstance(obj, (ipaddress.IPv4Address, ipaddress.IPv6Address)):
            return str(obj)
        if isinstance(obj, datetime.datetime):
            return obj.isoformat()
        return super().default(obj)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Process EML files to extract IOCs.")
    parser.add_argument("input_path", help="Path to the directory containing EML files or a single EML file.")
    parser.add_argument("--recursive", action="store_true", help="Process files in subdirectories recursively.")
    args = parser.parse_args()

    if os.path.isdir(args.input_path):
        report = process_eml_files(args.input_path, recursive=args.recursive)
    elif os.path.isfile(args.input_path) and magic.from_file(args.input_path, mime=True) == 'message/rfc822':
        report = [extract_iocs_from_eml(args.input_path)]
    else:
        logging.error("Invalid input path. Please provide a directory or a single EML file.")
        exit(1)

    if not report:
        logging.info("No IOCs found.")
    else:
        print(json.dumps(report, indent=4, cls=CustomJSONEncoder))