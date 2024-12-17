# Email IOC Extractor

This project extracts Indicators of Compromise (IOCs) from EML files and uploads them to Elasticsearch.

## Features

- Extracts sender email, sender IP, recipient emails, recipient domains, subject, links, and domains from EML files.
- Processes EML files in a directory, optionally recursively.
- Uploads extracted IOCs to Elasticsearch.

## Requirements

- Python 3.6+
- `pip` for managing Python packages

## Installation

1. Clone the repository:
    ```sh
    git clone https://github.com/rap-valerig/email-ioc-extractor.git
    cd email-ioc-extractor
    ```

2. Install the required Python packages:
    ```sh
    pip install -r requirements.txt
    ```

## Configuration

1. Create a `config.json` file in the project root with the following structure:
    ```json
    {
      "elasticsearch": {
        "url": "https://your-elasticsearch-url",
        "api_key": "your-elasticsearch-api-key"
      },
      "eml_directory": "/path/to/your/eml/files",
      "index_name": "emails_ioc",
      "pipeline": "your-pipeline"
    }
    ```

2. Set the environment variables for sensitive information:
    ```sh
    export ELASTICSEARCH_URL="https://your-elasticsearch-url"
    export ELASTICSEARCH_API_KEY="your-elasticsearch-api-key"
    ```

## Usage

### Extract IOCs from EML files

To extract IOCs from EML files, run the following command:
```sh
python email_iocs.py /path/to/your/eml/files --recursive