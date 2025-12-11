import requests
import json
import extruct
from w3lib.html import get_base_url
from urllib.parse import urljoin, urlparse
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from threading import Lock
import sys

SCHEMA_CHECKLIST = [
    ("Breadcrumbs", "BreadcrumbList"),
    ("FAQ", "FAQPage"),
    ("Article", "Article"),
    ("Video", "VideoObject"),
    ("Organization", "Organization"),
    ("How-to", "HowTo"),
    ("WebPage", "WebPage"),
    ("Product", "Product"),
    ("Review", "Review"),
    ("Person", "Person"),
    ("Event", "Event"),
    ("Recipe", "Recipe"),
    ("LocalBusiness", "LocalBusiness"),
    ("CreativeWork", "CreativeWork"),
    ("ItemList", "ItemList"),
    ("JobPosting", "JobPosting"),
    ("Course", "Course"),
    ("ImageObject", "ImageObject"),
    ("Service", "Service"),
]

# Common URL variations to check
URL_VARIATIONS = [
    "",
    "/about",
    "/about-us",
    "/products",
    "/services",
    "/solutions"
    "/blog",
    "blogs",
    "cyberglossary",
    "/news",
    "/resources",
    "/how-to",
    "/tutorials",
    "/guides",
    "/faq",
    "/help",
    "/support",
    "/contact",
    "/contact-us",
    "/reviews",
    "/testimonials",
    "/portfolio",
    "/cases",
    "/case-studies",
    "/team",
    "/careers",
    "/jobs",
    "/catalog",
    "/pricing",
    "/plans",
    "/login",
    "/signup",
    "/register",
]

def extract_schemas(url, timeout=10):
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.4472.124 Safari/537.36",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5",
        "DNT": "1",
        "Connection": "keep-alive",
        "Upgrade-Insecure-Requests": "1",
    }
    try:
        response = requests.get(url, headers=headers, timeout=timeout)
        response.raise_for_status()
        base_url = get_base_url(response.text, response.url)

        data = extruct.extract(
            response.text, base_url=base_url, syntaxes=["json-ld", "microdata", "rdfa"]
        )
        return data
    except requests.exceptions.RequestException:
        return None


def flatten_schema(schema_item):
    """Flatten nested schema items, including @graph structures."""
    if isinstance(schema_item, list):
        for item in schema_item:
            yield from flatten_schema(item)
    elif isinstance(schema_item, dict):
        if "@graph" in schema_item:
            yield from flatten_schema(schema_item["@graph"])
        yield schema_item


def extract_schema_names(schemas):
    schema_names = set()

    for item in flatten_schema(schemas.get("json-ld", [])):
        if "@type" in item:
            if isinstance(item["@type"], list):
                for t in item["@type"]:
                    schema_names.add(t)
            else:
                schema_names.add(item["@type"])

    for item in flatten_schema(schemas.get("microdata", [])):
        if "type" in item:
            if isinstance(item["type"], list):
                for t in item["type"]:
                    schema_names.add(t)
            else:
                schema_names.add(item["type"])

    for item in flatten_schema(schemas.get("rdfa", [])):
        if "type" in item:
            if isinstance(item["type"], list):
                for t in item["type"]:
                    schema_names.add(t)
            else:
                schema_names.add(item["type"])

    return sorted(schema_names)

def normalize_base_url(url):
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url
    
    parsed = urlparse(url)
    return f"{parsed.scheme}://{parsed.netloc}"

def process_single_url(args):
    url, index, total, timeout = args
    
    try:
        schemas = extract_schemas(url, timeout)
        
        if schemas:
            schema_names = extract_schema_names(schemas)
            if schema_names:
                processed_names = set()
                for name in schema_names:
                    if isinstance(name, str):
                        short_name = name.split('/')[-1]
                        processed_names.add(short_name)
                    else:
                        processed_names.add(str(name))
                
                return {
                    'url': url,
                    'success': True,
                    'schemas': processed_names,
                    'schema_count': len(processed_names),
                    'index': index
                }
            else:
                return {
                    'url': url,
                    'success': True,
                    'schemas': set(),
                    'schema_count': 0,
                    'index': index
                }
        else:
            return {
                'url': url,
                'success': False,
                'schemas': set(),
                'schema_count': 0,
                'index': index
            }
    except Exception as e:
        return {
            'url': url,
            'success': False,
            'schemas': set(),
            'schema_count': 0,
            'index': index,
            'error': str(e)
        }

def check_multiple_urls_threaded(base_url, max_workers=10, timeout=10, verbose=True):
    base_url = normalize_base_url(base_url)
    all_schemas = set()
    successful_urls = []
    failed_urls = []
    url_schemas = {}
    
    # Create list of URLs to check
    urls_to_check = []
    for i, variation in enumerate(URL_VARIATIONS):
        full_url = urljoin(base_url, variation)
        urls_to_check.append((full_url, i, len(URL_VARIATIONS), timeout))
    
    if verbose:
        print(f"Checking schema markup across {len(urls_to_check)} pages for: {base_url}")
        print(f"Using {max_workers} concurrent threads")
        print("=" * 60)
    
    progress_lock = Lock()
    completed_count = [0]
    
    def update_progress(result, total_urls, completed_count):
        with progress_lock:
            completed_count[0] += 1

    start_time = time.time()
    
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_url = {executor.submit(process_single_url, url_args): url_args[0] 
                        for url_args in urls_to_check}
        
        for future in as_completed(future_to_url):
            result = future.result()
            update_progress(result, len(urls_to_check), completed_count)
            
            if result['success']:
                successful_urls.append(result['url'])
                if result['schemas']:
                    all_schemas.update(result['schemas'])
                    url_schemas[result['url']] = result['schemas']
            else:
                failed_urls.append(result['url'])
    
    end_time = time.time()
    processing_time=end_time-start_time
    
    if verbose:
        print(f"\nCompleted in {processing_time:.2f} seconds")
        print(f"Average time per URL: {processing_time/len(urls_to_check):.2f} seconds")
    
    return all_schemas, successful_urls, failed_urls, url_schemas, processing_time

def display_results(all_schemas):
    if all_schemas:
        print("\nAll Unique Schema Types Found:")
        print("-" * 40)
        for schema in sorted(all_schemas):
            print(f"• {schema}")
    else:
        print("\nNo schema types found across all pages.")

def main():
    import argparse

    parser = argparse.ArgumentParser(
        description="Extract schema markups from multiple webpage variations using multithreading."
    )
    parser.add_argument("url", help="Base URL of the website to check")
    parser.add_argument(
        "--workers",
        type=int,
        default=20,
        help="Number of concurrent threads (default: 10)",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=10,
        help="Timeout for each request in seconds (default: 10)",
    )
    parser.add_argument(
        "--quiet",
        action="store_true",
        help="Reduce output verbosity",
    )
    parser.add_argument(
        "--full-schemas",
        action="store_true",
        help="Show full schema data for pages with schemas",
    )
    args = parser.parse_args()

    verbose = not args.quiet
    
    all_schemas, successful_urls, failed_urls, url_schemas, processing_time = check_multiple_urls_threaded(
        args.url, 
        max_workers=args.workers, 
        timeout=args.timeout,
        verbose=verbose
    )
    
    display_results(all_schemas)

    if args.full_schemas and url_schemas:
        print("\n" + "=" * 60)
        print("FULL SCHEMA DATA")
        print("=" * 60)
        for url in successful_urls:
            if url in url_schemas and url_schemas[url]:
                print(f"\n{url}:")
                print("-" * len(url))
                schemas = extract_schemas(url, args.timeout)
                if schemas:
                    print(json.dumps(schemas, indent=2))

if __name__ == "__main__":
    main()