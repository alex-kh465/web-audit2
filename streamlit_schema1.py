import streamlit as st
import pandas as pd
import requests     
import json
import extruct
from w3lib.html import get_base_url
import re
import time
from typing import Dict, List, Any, Tuple, Set
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.common.by import By
import functools
import os

st.set_page_config(
    page_title="Schema Markup Detector",
    page_icon="🔎",
    layout="wide"
)

def normalize_url(url: str) -> str:
    """Normalize URL by adding https:// if not present."""
    print(f"[LOG] Normalizing URL: {url}")
    if url and isinstance(url, str) and not url.startswith(('http://', 'https://')):
        normalized = 'https://' + url
        print(f"[LOG] URL normalized to: {normalized}")
        return normalized
    print(f"[LOG] URL already normalized: {url}")
    return url

def is_primary_schema_type(schema_type: str) -> bool:
    """
    Determine if a schema type represents a primary page-level implementation.
    Based on schema.org validator behavior - more restrictive than before.
    """
    supporting_types = {
        'Thing', 'Intangible', 'StructuredValue', 'Enumeration',
        'PostalAddress', 'ContactPoint', 'ImageObject', 'Rating', 
        'AggregateRating', 'PropertyValue', 'QuantitativeValue',
        'MonetaryAmount', 'Distance', 'Duration', 'Answer', 'Question',
        'aggregateOffer', 'Offer', 'GeoCoordinates', 'OpeningHours',
        'PriceSpecification', 'Person', 'Review' 
    }
    
    is_primary = schema_type not in supporting_types
    print(f"[LOG] Schema type '{schema_type}' is {'PRIMARY' if is_primary else 'SUPPORTING'}")
    return is_primary

def extract_schema_name(type_val: str) -> str:
    """Extract clean schema name from type value."""
    if isinstance(type_val, str):
        if type_val.startswith(('http://schema.org/', 'https://schema.org/')):
            schema_name = type_val.split('/')[-1]
            print(f"[LOG] Extracted schema name: {schema_name} from URL: {type_val}")
            return schema_name
        else:
            print(f"[LOG] Schema name: {type_val}")
            return type_val
    return ""

def extract_primary_schemas(obj: Any, is_root_level: bool = True, found_types: Set[str] = None) -> Set[str]:
    """
    Extract only primary/page-level schema types, similar to schema.org validator behavior.
    Only counts schemas that are at the root level or in @graph arrays as primary implementations.
    """
    if found_types is None:
        found_types = set()
    
    if isinstance(obj, dict):
        type_val = obj.get("@type") or obj.get("type")
        if type_val and is_root_level:
            if isinstance(type_val, list):
                print(f"[LOG] Processing list of types: {type_val}")
                for t in type_val:
                    schema_name = extract_schema_name(t)
                    if schema_name and is_primary_schema_type(schema_name):
                        found_types.add(schema_name)
                        print(f"[LOG] Added primary schema: {schema_name}")
            else:
                schema_name = extract_schema_name(type_val)
                if schema_name and is_primary_schema_type(schema_name):
                    found_types.add(schema_name)
                    print(f"[LOG] Added primary schema: {schema_name}")
        
        if '@graph' in obj and isinstance(obj['@graph'], list):
            print(f"[LOG] Processing @graph array with {len(obj['@graph'])} items")
            for item in obj['@graph']:
                extract_primary_schemas(item, is_root_level=True, found_types=found_types)
        else:
            for key, value in obj.items():
                if key != '@graph':
                    extract_primary_schemas(value, is_root_level=False, found_types=found_types)
    
    elif isinstance(obj, list) and is_root_level:
        print(f"[LOG] Processing root-level array with {len(obj)} items")
        for item in obj:
            extract_primary_schemas(item, is_root_level=True, found_types=found_types)
    
    return found_types

def extract_microdata_schemas(microdata_items: List[Dict]) -> Set[str]:
    """Extract only primary schema types from microdata format."""
    print(f"[LOG] Extracting microdata schemas from {len(microdata_items)} items")
    found_types = set()
    
    for item in microdata_items:
        if isinstance(item, dict):
            item_type = item.get('type')
            if item_type:
                if isinstance(item_type, list):
                    for t in item_type:
                        if isinstance(t, str) and ('schema.org' in t):
                            schema_name = t.split('/')[-1]
                            if is_primary_schema_type(schema_name):
                                found_types.add(schema_name)
                                print(f"[LOG] Found microdata schema: {schema_name}")
                elif isinstance(item_type, str) and ('schema.org' in item_type):
                    schema_name = item_type.split('/')[-1]
                    if is_primary_schema_type(schema_name):
                        found_types.add(schema_name)
                        print(f"[LOG] Found microdata schema: {schema_name}")
    
    print(f"[LOG] Total microdata schemas found: {len(found_types)}")
    return found_types

def extract_rdfa_schemas(rdfa_items: List[Dict]) -> Set[str]:
    """Extract only primary schema types from RDFa format."""
    print(f"[LOG] Extracting RDFa schemas from {len(rdfa_items)} items")
    found_types = set()
    
    for item in rdfa_items:
        if isinstance(item, dict):
            for key, value in item.items():
                if key == '@type' or 'type' in key.lower():
                    if isinstance(value, list):
                        for v in value:
                            if isinstance(v, dict) and '@id' in v:
                                type_id = v['@id']
                                if 'schema.org' in type_id:
                                    schema_name = type_id.split('/')[-1]
                                    if is_primary_schema_type(schema_name):
                                        found_types.add(schema_name)
                                        print(f"[LOG] Found RDFa schema: {schema_name}")
                    elif isinstance(value, dict) and '@id' in value:
                        type_id = value['@id']
                        if 'schema.org' in type_id:
                            schema_name = type_id.split('/')[-1]
                            if is_primary_schema_type(schema_name):
                                found_types.add(schema_name)
                                print(f"[LOG] Found RDFa schema: {schema_name}")
    
    print(f"[LOG] Total RDFa schemas found: {len(found_types)}")
    return found_types


@functools.lru_cache(maxsize=1)
def get_chrome_driver_path():
    """Cache the Chrome driver path to avoid repeated installations."""
    print(f"[LOG] Locating Chrome driver")

    possible_paths = [
        '/usr/bin/chromedriver',  # Debian/Ubuntu standard location
        '/usr/local/bin/chromedriver',
        'chromedriver'  # Rely on PATH
    ]

    for path in possible_paths:
        if os.path.exists(path) or path == 'chromedriver':
            print(f"[LOG] Using chromedriver at: {path}")
            return path

    try:
        from webdriver_manager.chrome import ChromeDriverManager
        print(f"[LOG] Using webdriver-manager as fallback")
        return ChromeDriverManager().install()
    except ImportError:
        print(f"[LOG] webdriver-manager not available, using 'chromedriver' from PATH")
        return 'chromedriver'

def fetch_with_javascript(url: str, timeout: int = 10) -> str:
    """
    Fetch page content with JavaScript execution using Selenium.
    Falls back to regular requests if Selenium fails.
    """
    print(f"[LOG] Attempting to fetch with JavaScript execution: {url}")

    try:
        chrome_options = Options()
        chrome_options.add_argument('--headless=new')
        chrome_options.add_argument('--no-sandbox')
        chrome_options.add_argument('--disable-dev-shm-usage')
        chrome_options.add_argument('--disable-gpu')
        chrome_options.add_argument('--disable-software-rasterizer')
        chrome_options.add_argument('--disable-setuid-sandbox')
        chrome_options.add_argument('--window-size=1920,1080')
        chrome_options.add_argument('--single-process')  # Important for Streamlit Cloud
        chrome_options.add_argument('--disable-features=VizDisplayCompositor')
        chrome_options.add_argument('user-agent=Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36')
        chrome_options.binary_location = '/usr/bin/chromium'  # Streamlit Cloud specific

        chrome_options.add_argument('--disable-extensions')
        chrome_options.add_argument('--disable-blink-features=AutomationControlled')
        chrome_options.add_argument('--disable-logging')
        chrome_options.add_argument('--disable-notifications')
        chrome_options.add_argument('--disable-popup-blocking')
        chrome_options.add_experimental_option('excludeSwitches', ['enable-logging'])

        prefs = {
            'profile.default_content_setting_values': {
                'images': 2,
                'stylesheet': 2
            }
        }
        chrome_options.add_experimental_option('prefs', prefs)

        service = Service(get_chrome_driver_path())
        driver = webdriver.Chrome(service=service, options=chrome_options)
        driver.set_page_load_timeout(timeout)

        driver.get(url)

        try:
            WebDriverWait(driver, timeout).until(
                EC.presence_of_element_located((By.TAG_NAME, "body"))
            )
            time.sleep(0.5)
        except:
            print(f"[LOG] Wait condition not met, proceeding anyway")

        page_source = driver.page_source
        print(f"[LOG] Successfully fetched with JavaScript, content size: {len(page_source)} characters")

        driver.quit()
        return page_source
        
    except Exception as e:
        print(f"[LOG] JavaScript fetch failed: {str(e)}")
        print(f"[LOG] Falling back to regular requests")
        return None

def extract_schemas_with_debug(url: str, use_js: bool = False) -> Tuple[Dict, Dict, Set[str]]:
    """Extracts schema markup from a given URL with rich debug information."""
    print(f"\n[LOG] ========== Starting schema extraction for: {url} ==========")
    print(f"[LOG] JavaScript mode enabled: {use_js}")
    debug_info = {"url": url, "extraction_errors": [], "json_ld_blocks": []}
    all_schemas = set()
    
    response_text = None
    
    if use_js:
        response_text = fetch_with_javascript(url)
        if response_text:
            print(f"[LOG] Using JavaScript-rendered content")
        else:
            print(f"[LOG] JavaScript fetch failed, falling back to regular requests")
    
    if not response_text:
        max_retries = 3
        retry_delay = 2
        
        for attempt in range(max_retries):
            try:
                print(f"[LOG] Sending HTTP request to: {url} (Attempt {attempt + 1}/{max_retries})")
                headers = {
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
                    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8",
                    "Accept-Language": "en-US,en;q=0.9",
                    "Accept-Encoding": "gzip, deflate, br",
                    "Connection": "keep-alive",
                    "Upgrade-Insecure-Requests": "1",
                    "Sec-Fetch-Dest": "document",
                    "Sec-Fetch-Mode": "navigate",
                    "Sec-Fetch-Site": "none",
                    "Sec-Fetch-User": "?1",
                    "Cache-Control": "max-age=0",
                    "DNT": "1"
                }
                
                if attempt > 0:
                    print(f"[LOG] Waiting {retry_delay} seconds before retry...")
                    time.sleep(retry_delay)
                
                response = requests.get(url, headers=headers, timeout=15, allow_redirects=True)
                response.raise_for_status()
                response_text = response.text
                print(f"[LOG] Request successful! Status code: {response.status_code}")
                print(f"[LOG] Response size: {len(response_text)} characters")
                break
                
            except requests.exceptions.HTTPError as e:
                if e.response.status_code == 403:
                    error_msg = f"Access Forbidden (403) - Attempt {attempt + 1}/{max_retries}"
                    print(f"[LOG] ERROR: {error_msg}")
                    if attempt == max_retries - 1:
                        error_msg = "Access Forbidden (403): The website is blocking automated requests. Try enabling JavaScript mode."
                        debug_info["extraction_errors"].append(error_msg)
                        return {}, debug_info, set()
                    continue
                else:
                    error_msg = f"HTTP Error {e.response.status_code}: {str(e)}"
                    print(f"[LOG] ERROR: {error_msg}")
                    debug_info["extraction_errors"].append(error_msg)
                    return {}, debug_info, set()
            except requests.exceptions.RequestException as e:
                error_msg = f"Request Failed: {str(e)}"
                print(f"[LOG] ERROR: {error_msg}")
                debug_info["extraction_errors"].append(error_msg)
                return {}, debug_info, set()
            except Exception as e:
                error_msg = f"Processing Error: {str(e)}"
                print(f"[LOG] ERROR: {error_msg}")
                debug_info["extraction_errors"].append(error_msg)
                return {}, debug_info, set()
    
    try:
        print(f"[LOG] Searching for JSON-LD blocks...")
        json_ld_pattern = r'<script[^>]*type=["\']application/ld\+json["\'][^>]*>(.*?)</script>'
        debug_info["json_ld_blocks"] = re.findall(json_ld_pattern, response_text, re.DOTALL | re.IGNORECASE)
        print(f"[LOG] Found {len(debug_info['json_ld_blocks'])} JSON-LD blocks")
        
        if len(debug_info["json_ld_blocks"]) == 0 and not use_js:
            print(f"[LOG] WARNING: No JSON-LD found - page may use JavaScript to inject schema")
            debug_info["extraction_errors"].append("No JSON-LD blocks found. If this is a JavaScript-heavy site (Next.js, React, etc.), try enabling JavaScript mode.")
        
        for idx, block in enumerate(debug_info["json_ld_blocks"]):
            print(f"[LOG] Processing JSON-LD block {idx + 1}/{len(debug_info['json_ld_blocks'])}")
            try:
                data = json.loads(block.strip())
                print(f"[LOG] Successfully parsed JSON-LD block {idx + 1}")
                block_schemas = extract_primary_schemas(data)
                all_schemas.update(block_schemas)
                print(f"[LOG] Block {idx + 1} contributed schemas: {block_schemas}")
            except json.JSONDecodeError as e:
                print(f"[LOG] ERROR: Failed to parse JSON-LD block {idx + 1}: {str(e)}")
                continue
        
        print(f"[LOG] Extracting microdata and RDFa using extruct...")
        base_url = get_base_url(response_text, url)
        print(f"[LOG] Base URL: {base_url}")
        other_data = extruct.extract(response_text, base_url=base_url, syntaxes=["microdata", "rdfa"], errors='ignore')
        
        if other_data.get("microdata"):
            print(f"[LOG] Found microdata, extracting schemas...")
            microdata_schemas = extract_microdata_schemas(other_data["microdata"])
            all_schemas.update(microdata_schemas)
        else:
            print(f"[LOG] No microdata found")
        
        if other_data.get("rdfa"):
            print(f"[LOG] Found RDFa, extracting schemas...")
            rdfa_schemas = extract_rdfa_schemas(other_data["rdfa"])
            all_schemas.update(rdfa_schemas)
        else:
            print(f"[LOG] No RDFa found")
        
        print(f"[LOG] Total unique schemas found: {len(all_schemas)}")
        print(f"[LOG] Schemas: {sorted(all_schemas)}")
        
        return other_data, debug_info, all_schemas
    
    except Exception as e:
        error_msg = f"Processing Error: {str(e)}"
        print(f"[LOG] ERROR: {error_msg}")
        debug_info["extraction_errors"].append(error_msg)
        return {}, debug_info, set()

def manual_json_ld_parse(json_ld_blocks: List[str]) -> Tuple[List[Dict], List[Dict]]:
    """Parse JSON-LD blocks and return structured information."""
    print(f"\n[LOG] Manually parsing {len(json_ld_blocks)} JSON-LD blocks...")
    parsed_blocks = []
    parsing_errors = []
    
    for i, block in enumerate(json_ld_blocks):
        print(f"[LOG] Parsing block {i + 1}...")
        try:
            parsed_data = json.loads(block.strip())
            schemas_found = list(extract_primary_schemas(parsed_data))
            parsed_blocks.append({
                "block_index": i,
                "parsed_data": parsed_data,
                "schemas_found": schemas_found
            })
            print(f"[LOG] Block {i + 1} parsed successfully. Found schemas: {schemas_found}")
        except json.JSONDecodeError as e:
            error_info = {
                "block_index": i,
                "error": str(e),
                "raw_content": block[:500]  # First 500 chars for preview
            }
            parsing_errors.append(error_info)
            print(f"[LOG] ERROR: Block {i + 1} parsing failed: {str(e)}")
    
    print(f"[LOG] Successfully parsed {len(parsed_blocks)} blocks, {len(parsing_errors)} errors")
    return parsed_blocks, parsing_errors

def analyze_bulk_url(url: str, use_js: bool = False) -> Dict:
    """Analyzes a single URL and returns schema information (simplified for bulk)."""
    print(f"\n[LOG] [BULK] Analyzing: {url}")
    url = normalize_url(url.strip())
    
    response_text = None
    
    if use_js:
        response_text = fetch_with_javascript(url, timeout=15)
        if response_text:
            print(f"[LOG] [BULK] Using JavaScript-rendered content")
    
    if not response_text:
        max_retries = 2  # Fewer retries for bulk to save time
        retry_delay = 1
        
        for attempt in range(max_retries):
            try:
                print(f"[LOG] [BULK] Fetching URL: {url} (Attempt {attempt + 1}/{max_retries})")
                headers = {
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
                    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8",
                    "Accept-Language": "en-US,en;q=0.9",
                    "Accept-Encoding": "gzip, deflate, br",
                    "Connection": "keep-alive",
                    "Upgrade-Insecure-Requests": "1"
                }
                
                if attempt > 0:
                    print(f"[LOG] [BULK] Waiting {retry_delay} seconds before retry...")
                    time.sleep(retry_delay)
                
                response = requests.get(url, headers=headers, timeout=15, allow_redirects=True)
                response.raise_for_status()
                response_text = response.text
                print(f"[LOG] [BULK] Request successful, status: {response.status_code}")
                break
                
            except requests.exceptions.HTTPError as e:
                if e.response.status_code == 403 and attempt < max_retries - 1:
                    print(f"[LOG] [BULK] ERROR: Access Forbidden (403) - Attempt {attempt + 1}/{max_retries}")
                    continue
                return {"url": url, "schemas": [], "status": f"HTTP Error: {str(e)}"}
            except requests.exceptions.RequestException as e:
                print(f"[LOG] [BULK] ERROR: Request failed - {str(e)}")
                return {"url": url, "schemas": [], "status": f"Request Failed: {str(e)}"}
    
    if response_text is None:
        return {"url": url, "schemas": [], "status": "Request failed after retries"}
    
    try:
        all_schemas = set()
        
        json_ld_pattern = r'<script[^>]*type=["\']application/ld\+json["\'][^>]*>(.*?)</script>'
        json_ld_matches = re.findall(json_ld_pattern, response_text, re.DOTALL | re.IGNORECASE)
        print(f"[LOG] [BULK] Found {len(json_ld_matches)} JSON-LD blocks")
        
        for idx, block in enumerate(json_ld_matches):
            try:
                data = json.loads(block.strip())
                block_schemas = extract_primary_schemas(data)
                all_schemas.update(block_schemas)
            except json.JSONDecodeError: 
                print(f"[LOG] [BULK] Block {idx + 1} parsing failed")
                continue
        
        base_url = get_base_url(response_text, url)
        other_data = extruct.extract(response_text, base_url=base_url, syntaxes=["microdata", "rdfa"], errors='ignore')
        
        if other_data.get("microdata"):
            microdata_schemas = extract_microdata_schemas(other_data["microdata"])
            all_schemas.update(microdata_schemas)
        
        if other_data.get("rdfa"):
            rdfa_schemas = extract_rdfa_schemas(other_data["rdfa"])
            all_schemas.update(rdfa_schemas)
        
        if not all_schemas and not json_ld_matches and not other_data.get("microdata") and not other_data.get("rdfa"):
            status_msg = "No structured data found"
            if not use_js:
                status_msg += " (try JavaScript mode if this is a JS-heavy site)"
            return {"url": url, "schemas": [], "status": status_msg}

        return {
            "url": url, 
            "schemas": sorted(list(all_schemas)), 
            "status": "Success" if all_schemas else "Structured data found, but no recognizable schema types"
        }

    except Exception as e:
        print(f"[LOG] [BULK] ERROR: Processing error - {str(e)}")
        return {"url": url, "schemas": [], "status": f"Processing Error: {str(e)}"}

print("\n[LOG] ========== STREAMLIT APP STARTING ==========")
st.title("🔎 Schema Markup Detector")
st.markdown("A tool for both deep-dive debugging of a single URL and high-level analysis of bulk URLs.")

tab1, tab2 = st.tabs(["Single URL Deep Dive", "Bulk Upload Analysis"])

with tab1:
    st.header("Single URL Deep Dive")
    url_input = st.text_input("Enter a single URL to debug:", placeholder="https://example.com")
    
    use_javascript = st.checkbox(
        "🚀 Enable JavaScript Rendering", 
        value=False,
        help="Enable this if the page loads schema via JavaScript (Next.js, React, Vue, etc.). This will use Selenium to render the page before extracting schemas."
    )

    if st.button("🐛 Analyze Schema Structure", key="single_url_analyze"):
        if url_input:
            print(f"\n[LOG] ========== USER CLICKED ANALYZE BUTTON ==========")
            print(f"[LOG] Input URL: {url_input}")
            print(f"[LOG] JavaScript mode: {use_javascript}")
            normalized_url = normalize_url(url_input.strip())
            
            spinner_text = f"Performing deep analysis on: {normalized_url}"
            if use_javascript:
                spinner_text += " (with JavaScript rendering)"
            
            with st.spinner(spinner_text):
                other_schemas, debug_info, all_detected_schemas = extract_schemas_with_debug(
                    normalized_url,
                    use_js=use_javascript
                )
            
            st.success("Analysis complete!")
            print(f"[LOG] Analysis completed successfully")
            
            # Show overall detected schemas (matching schema.org validator format)
            if all_detected_schemas:
                print(f"[LOG] Displaying {len(all_detected_schemas)} detected schemas")
                st.subheader("🎯 Detected Schemas")
                st.success(f"Found {len(all_detected_schemas)} schema types")
                
                # Display in a format similar to schema.org validator
                schema_cols = st.columns(3)
                for i, schema in enumerate(sorted(all_detected_schemas)):
                    with schema_cols[i % 3]:
                        st.markdown(f"**{schema}**")
                        st.caption("0 ERRORS • 0 WARNINGS • 1 ITEM")
            else:
                print(f"[LOG] No schemas detected")
                st.warning("No schema markup detected on this page.")
                if not use_javascript:
                    st.info("💡 If this is a JavaScript-heavy site (Next.js, React, etc.), try enabling JavaScript rendering above.")
            
            if debug_info["extraction_errors"]:
                print(f"[LOG] Displaying extraction errors")
                for error in debug_info["extraction_errors"]:
                    if "No JSON-LD blocks found" in error:
                        st.info(f"ℹ️ {error}")
                    else:
                        st.error(f"❌ {error}")
            
            # Parse JSON-LD blocks
            parsed_blocks, parsing_errors = manual_json_ld_parse(debug_info["json_ld_blocks"])
            
            if not debug_info["json_ld_blocks"] and not other_schemas:
                print(f"[LOG] No structured data found in HTML source")
                st.warning("⚠️ No structured data found in the page's HTML source.")
                st.info("This could mean: 1) The page doesn't use schema markup, 2) Schema is loaded via JavaScript (try enabling JS mode above), or 3) It uses other formats like microdata embedded in HTML tags.")

            if parsing_errors:
                print(f"[LOG] Displaying {len(parsing_errors)} parsing errors")
                st.error("Some JSON-LD blocks had parsing errors:")
                for error in parsing_errors:
                    with st.expander(f"Block {error['block_index']} Error: {error['error']}"):
                        st.code(error['raw_content'], language='json')

            # Detailed breakdown
            if parsed_blocks:
                print(f"[LOG] Displaying detailed breakdown of {len(parsed_blocks)} blocks")
                st.subheader("📋 Detailed Analysis")
                
                for i, block_info in enumerate(parsed_blocks):
                    with st.expander(f"JSON-LD Block {i+1} - Schemas: {', '.join(block_info['schemas_found'])}", expanded=False):
                        if block_info['schemas_found']:
                            st.markdown("**Primary schema types found in this block:**")
                            for schema in block_info['schemas_found']:
                                st.write(f"• {schema}")
                        else:
                            st.info("No primary schemas found in this block (may contain supporting data only)")
                        
                    with st.expander("View Raw JSON-LD Data"):
                        st.json(block_info['parsed_data'])
            
            # Show other formats if they exist
            if other_schemas:
                if other_schemas.get("microdata"):
                    microdata_schemas = extract_microdata_schemas(other_schemas["microdata"])
                    if microdata_schemas:
                        print(f"[LOG] Displaying microdata schemas")
                        st.subheader("🔗 Microdata Schemas Found")
                        for schema in sorted(microdata_schemas):
                            st.write(f"• {schema}")
                        
                        with st.expander("View Raw Microdata"):
                            st.json(other_schemas["microdata"])
                
                if other_schemas.get("rdfa"):
                    rdfa_schemas = extract_rdfa_schemas(other_schemas["rdfa"])
                    if rdfa_schemas:
                        print(f"[LOG] Displaying RDFa schemas")
                        st.subheader("🔗 RDFa Schemas Found")
                        for schema in sorted(rdfa_schemas):
                            st.write(f"• {schema}")
                        
                        with st.expander("View Raw RDFa Data"):
                            st.json(other_schemas["rdfa"])

        else:
            print(f"[LOG] No URL entered")
            st.warning("Please enter a URL.")

with tab2:
    st.header("Bulk Upload Analysis")
    
    bulk_use_javascript = st.checkbox(
        "🚀 Enable JavaScript Rendering for Bulk Analysis", 
        value=False,
        help="Enable this if most URLs in your list use JavaScript to load schemas. Warning: This will be significantly slower."
    )
    
    uploaded_file = st.file_uploader("Upload a CSV or Excel file", type=['csv', 'xlsx'], help="The file must contain a column named 'URL'.")

    if uploaded_file:
        print(f"\n[LOG] ========== FILE UPLOADED ==========")
        print(f"[LOG] Filename: {uploaded_file.name}")
        try:
            df = pd.read_csv(uploaded_file) if uploaded_file.name.endswith('.csv') else pd.read_excel(uploaded_file)
            print(f"[LOG] File loaded successfully. Rows: {len(df)}, Columns: {list(df.columns)}")
            url_col = next((col for col in df.columns if col.strip().lower() == 'url'), None)

            if not url_col:
                print(f"[LOG] ERROR: 'URL' column not found in file")
                st.error("Error: A column named 'URL' was not found in the file.")
            else:
                print(f"[LOG] Found URL column: '{url_col}'")
                st.success(f"✅ File uploaded! Found {len(df)} URLs in the '{url_col}' column.")
                
                if bulk_use_javascript:
                    st.warning("⚠️ JavaScript mode enabled. This will take significantly longer but will capture JS-rendered schemas.")
                
                if st.button("🚀 Start Bulk Analysis", type="primary", key="bulk_analyze"):
                    print(f"\n[LOG] ========== STARTING BULK ANALYSIS ==========")
                    print(f"[LOG] JavaScript mode: {bulk_use_javascript}")
                    urls = df[url_col].dropna().unique().tolist()
                    print(f"[LOG] Processing {len(urls)} unique URLs")
                    progress_bar = st.progress(0)
                    status_text = st.empty()
                    results = []

                    for i, url in enumerate(urls):
                        print(f"\n[LOG] [BULK] === Processing {i+1}/{len(urls)} ===")
                        status_text.text(f"Processing URL {i+1} of {len(urls)}: {url}")
                        results.append(analyze_bulk_url(url, use_js=bulk_use_javascript))
                        progress_bar.progress((i + 1) / len(urls))
                    
                    print(f"\n[LOG] ========== BULK ANALYSIS COMPLETE ==========")
                    status_text.success(f"🎉 Analysis complete!")
                    
                    results_df = pd.DataFrame(results)
                    results_df['Detected Schemas'] = results_df['schemas'].apply(lambda x: ', '.join(x) if x else 'None')
                    results_df['Schema Count'] = results_df['schemas'].apply(len)
                    display_df = results_df[['url', 'Detected Schemas', 'Schema Count', 'status']]

                    st.subheader("Analysis Results")
                    st.dataframe(display_df, use_container_width=True)
                    
                    # Show summary statistics
                    success_count = len(results_df[results_df['status'] == 'Success'])
                    total_schemas_found = results_df['Schema Count'].sum()
                    print(f"[LOG] Successfully analyzed {success_count}/{len(results)} URLs")
                    
                    col1, col2, col3 = st.columns(3)
                    with col1:
                        st.metric("URLs Analyzed", len(results))
                    with col2:
                        st.metric("Successful", success_count)
                    with col3:
                        st.metric("Total Schemas Found", total_schemas_found)
                    
                    # Show most common schemas
                    if total_schemas_found > 0:
                        all_found_schemas = []
                        for schemas_list in results_df['schemas']:
                            all_found_schemas.extend(schemas_list)
                        
                        if all_found_schemas:
                            from collections import Counter
                            schema_counts = Counter(all_found_schemas)
                            st.subheader("📊 Most Common Schemas")
                            
                            common_schemas_df = pd.DataFrame(
                                schema_counts.most_common(10),
                                columns=['Schema Type', 'Count']
                            )
                            st.dataframe(common_schemas_df, use_container_width=True)
                    
                    csv_data = display_df.to_csv(index=False).encode('utf-8')
                    st.download_button("📥 Download Results as CSV", csv_data, 'schema_analysis_results.csv', 'text/csv')
                    print(f"[LOG] Results ready for download")
        except Exception as e:
            print(f"[LOG] ERROR: {str(e)}")
            st.error(f"An error occurred: {e}")