import logging
import json
import os
from elasticsearch import Elasticsearch
import email_iocs

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Load configuration from config.json
config_path = 'config.json'
if not os.path.exists(config_path):
    logging.error(f"Configuration file {config_path} not found.")
    exit(1)

with open(config_path, 'r') as config_file:
    config = json.load(config_file)

# Use environment variables for sensitive information
es_url = os.getenv('ELASTICSEARCH_URL', config['elasticsearch']['url'])
es_api_key = os.getenv('ELASTICSEARCH_API_KEY', config['elasticsearch']['api_key'])

client = Elasticsearch(
    es_url,
    api_key=es_api_key
)

# API key should have cluster monitor rights
try:
    client.info()
    logging.info("Connected to Elasticsearch successfully.")
except Exception as e:
    logging.error(f"Failed to connect to Elasticsearch: {e}")
    exit(1)

template = {"index": {"_index": config['index_name']}}
documents = []

try:
    report = email_iocs.process_eml_files(config['eml_directory'])
    logging.info("Processed EML files successfully.")
except Exception as e:
    logging.error(f"Failed to process EML files: {e}")
    exit(1)

for line in report:
    documents.append(template)
    documents.append(line)

try:
    client.bulk(operations=documents, pipeline=config['pipeline'])
    logging.info("Uploaded documents to Elasticsearch successfully.")
except Exception as e:
    logging.error(f"Failed to upload documents to Elasticsearch: {e}")

print()