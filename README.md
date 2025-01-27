### DsSScan 

This tool scans for .DS_Store file disclosures and attempts to extract and enumerate hidden or sensitive file paths revealed in .DS_Store files. It is useful for identifying misconfigurations in web applications or servers that expose such files.

Features
URL Enumeration: Scans single or multiple URLs for .DS_Store file disclosure.
Multithreading: Supports multithreaded scanning for faster results.
Path Traversal Prevention: Validates extracted paths to prevent directory traversal exploits.
Error Handling: Retries HTTP requests with configurable timeouts and logs errors.
Output Management: Saves results organized by HTTP status codes in the specified output directory.
Recursive Scanning: Parses .DS_Store files to discover and queue additional files or directories for scanning.
Configurable Options: Allows customization of threads, timeout, and saving .DS_Store URLs.
##

### Setup
(Python >= 3.7)  
`git clone https://github.com/jionin-real/dssscan.git`  
`cd dssscan`   
`pip install -r requirements.txt`  

##
### Usage
Examples:  
Scanning a single URL: `dssscan -u https://example.com/.DS_Store` 

Scanning from a list of URLs (urls.txt): `dssscan -l urls.txt`

### All parameters:  
```
usage: dssscan [-h] [-u URL] [-l URL_LIST] [-o OUTPUT] [-t THREADS] [--timeout TIMEOUT] [-ds]

optional arguments:
  -h, --help            Show this message and exit.
  -u URL, --url URL     Initial URL (e.g., https://example.com/.DS_Store).
  -l URL_LIST, --list URL_LIST
                        A file with a list of URLs to scan.
  -o OUTPUT, --output OUTPUT
                        The directory to save the results (default: “results”).
  -t THREADS, --threads THREADS
                        Number of streams (default: 10).
  --timeout TIMEOUT     Timeout for HTTP requests in seconds (default: 10).
  -ds, --save-ds       Keep the URL with `.DS_Store` in the results.
```
