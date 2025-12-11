import streamlit as st
import pandas as pd
import re
import requests
import extruct
from w3lib.html import get_base_url
from urllib.parse import urljoin, urlparse
from concurrent.futures import ThreadPoolExecutor
import streamlit as st
import pandas as pd
from collections import Counter
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
import requests
import re
import logging
from urllib3.exceptions import InsecureRequestWarning
from modules.helper_function import*

# Disable SSL warnings
requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

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

URL_VARIATIONS = [
    "",
    "/about",
    "/about-us",
    "/products",
    "/services",
    "/solutions",
    "/blog",
    "/blogs",
    "/cyberglossary",
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
    "/resources/cyberglossary",
]

def is_valid_page_url(url):
    if re.search(r'\.(jpg|jpeg|png|gif|bmp|pdf|doc|docx|xls|xlsx|css|js)$', url, re.IGNORECASE):
        return False
    if "wp-content" in url.lower() or "wp-uploads" in url.lower():
        return False
    return True

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

def get_domain_from_df(df):
    if df is not None and len(df) > 0 and "Address" in df.columns:
        first_url = df["Address"].iloc[0]
        if "://" in first_url:
            return first_url.split("/")[2]
        else:
            return first_url.split("/")[0]
    return None

def check_schema_markup(domain, max_workers=10, timeout=8):
    base_url = normalize_base_url(domain)
    all_schemas = set()
    
    try:
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = []
            
            for variation in URL_VARIATIONS:
                full_url = urljoin(base_url, variation)
                future = executor.submit(extract_schemas, full_url, timeout)
                futures.append((future, full_url))
            
            for future, url in futures:
                try:
                    schemas = future.result(timeout=timeout + 2) 
                    if schemas:
                        schema_names = extract_schema_names(schemas)
                        all_schemas.update(schema_names)
                except Exception as e:
                    continue
                    
        return all_schemas
    except Exception as e:
        print(f"Error in check_schema_markup: {str(e)}")
        return set()
    
def update_schema_markup_analysis(df, report, expected_outcomes, sources):
    domain = get_domain_from_df(df)
    
    if domain:
        try:
            with st.spinner(f"Checking schema markup for {domain}... (this may take a moment)"):
                found_schemas = check_schema_markup(domain)
            
            if found_schemas:
                schema_list = sorted(list(found_schemas))
                current_value = f"Found {len(schema_list)} types: {', '.join(schema_list)}"

                if len(schema_list) >= 5:
                    status = "✅ Pass"
                elif len(schema_list) >= 2:
                    status = "ℹ️ Review"
                else:
                    status = "❌ Fail"
            else:
                current_value = "No schema markup detected"
                status = "❌ Fail"
                
        except Exception as e:
            current_value = f"Error checking schemas: {str(e)}"
            status = "ℹ️ Not Available"
            print(f"Schema analysis error: {str(e)}")
    else:
        current_value = "Cannot extract domain from data"
        status = "ℹ️ Not Available"
    
    report["Category"].append("Metadata & Schema")
    report["Parameters"].append("Schema Markup")
    report["Current Value"].append(current_value)
    report["Expected Value"].append(expected_outcomes["Schema Markup"])
    report["Source"].append(sources["Schema Markup"])
    report["Status"].append(status)
    
def analyze_screaming_frog_data(df, alt_tag_df=None, orphan_pages_df=None, sitemap_success=None, robots_success=None):
    expected_outcomes = {
        "Website performance on desktop": "Score > 90",
        "Website performance on mobile": "Score > 80",
        "Core Web Vitals on desktop": "Pass",
        "Core Web Vitals on mobile": "Pass",
        "Accessibility Score": "Score > 90",
        "SEO Score": "Score > 90",
        "Mobile friendliness": "Pass",
        "Indexed pages": "All active pages are indexed",
        "Non indexed pages": "No active pages are in no index state.\nMinimal or no indexed pages",
        "Robots.txt file optimization": "Optimized",
        "Sitemap file optimization": "All active website URLs are part of sitemap",
        "Broken internal links (404)": "0 broken links",
        "Broken external links": "0 broken links",
        "Broken backlinks": "0 broken backlinks",
        "Broken Images": "0 broken Images",
        "Orphan page": "No orphan page",
        "Canonical Errors": "No page with canonical error",
        "Information architecture": "Site structure & navigation is well defined & easy to understand",
        "Header tags structure": "Content structure is well-defined and easy to understand",
        "Backlinks": "No of backlinks",
        "Domain authority": "DA >70",
        "Spam Score": "Score <5",
        "Duplicate content": "Minimal or no pages with issues",
        "Img alt tag": "Minimal or no pages with issues",
        "Duplicate & missing H1": "Minimal or no pages with issues",
        "Duplicate & missing meta title": "Minimal or no pages with issues",
        "Duplicate & missing description": "Minimal or no pages with issues",
        "Schema Markup": "Schema implementation opportunities",
    }

    sources = {
        "Website performance on desktop": "Pagespeedinsights",
        "Website performance on mobile": "Pagespeedinsights",
        "Core Web Vitals on desktop": "Pagespeedinsights",
        "Core Web Vitals on mobile": "Pagespeedinsights",
        "Accessibility Score": "Pagespeedinsights",
        "SEO Score": "Pagespeedinsights",
        "Mobile friendliness": "Manual",
        "Indexed pages": "Google search console",
        "Non indexed pages": "Google search console",
        "Robots.txt file optimization": "Manual",
        "Sitemap file optimization": "Manual",
        "Broken internal links (404)": "Screaming frog",
        "Broken external links": "Ahrefs",
        "Broken backlinks": "Ahrefs",
        "Broken Images": "Manual",
        "Orphan page": "Screaming frog",
        "Canonical Errors": "Screaming frog",
        "Information architecture": "Ahrefs",
        "Header tags structure": "Manual",
        "Backlinks": "Ahrefs",
        "Domain authority": "Moz",
        "Spam Score": "Moz",
        "Duplicate content": "Screaming frog",
        "Img alt tag": "Screaming frog",
        "Duplicate & missing H1": "Screaming frog",
        "Duplicate & missing meta title": "Screaming frog",
        "Duplicate & missing description": "Screaming frog",
        "Schema Markup": "Automated Schema Detection"
    }

    report = {
        "Category": [],
        "Parameters": [],
        "Current Value": [],
        "Expected Value": [],
        "Source": [],
        "Status": [],
    }

    performance_metrics = [
        "Website performance on desktop",
        "Website performance on mobile",
        "Core Web Vitals on desktop",
        "Core Web Vitals on mobile",
        "Accessibility Score",
        "SEO Score",
        "Mobile friendliness",
    ]

    for metric in performance_metrics:
        report["Category"].append("Performance & Core Web Vitals")
        report["Parameters"].append(metric)
        report["Current Value"].append("N/A")
        report["Expected Value"].append(expected_outcomes[metric])
        report["Source"].append(sources[metric])
        report["Status"].append("ℹ️ Not Available")

    if "Indexability" in df.columns and "Indexability Status" in df.columns:
        indexed_pages = len(df[df["Indexability"] == "Indexable"])
        report["Category"].append("Crawling & Indexing")
        report["Parameters"].append("Indexed pages")
        report["Current Value"].append(indexed_pages)
        report["Expected Value"].append(expected_outcomes["Indexed pages"])
        report["Source"].append(sources["Indexed pages"])
        report["Status"].append("ℹ️ Review")

        non_indexed_pages = len(
            df[df["Indexability Status"].str.contains("noindex", na=False)]
        )
        report["Category"].append("Crawling & Indexing")
        report["Parameters"].append("Non indexed pages")
        report["Current Value"].append(non_indexed_pages)
        report["Expected Value"].append(expected_outcomes["Non indexed pages"])
        report["Source"].append(sources["Non indexed pages"])
        report["Status"].append("ℹ️ Review" if non_indexed_pages > 0 else "✅ Pass")
    else:
        report["Category"].append("Crawling & Indexing")
        report["Parameters"].append("Indexed pages")
        report["Current Value"].append("N/A")
        report["Expected Value"].append(expected_outcomes["Indexed pages"])
        report["Source"].append(sources["Indexed pages"])
        report["Status"].append("ℹ️ Not Available")

        report["Category"].append("Crawling & Indexing")
        report["Parameters"].append("Non indexed pages")
        report["Current Value"].append("N/A")
        report["Expected Value"].append(expected_outcomes["Non indexed pages"])
        report["Source"].append(sources["Non indexed pages"])
        report["Status"].append("ℹ️ Not Available")

    report["Category"].append("Crawling & Indexing")
    report["Parameters"].append("Robots.txt file optimization")
    report["Current Value"].append("Available" if robots_success else "N/A")
    report["Expected Value"].append(expected_outcomes["Robots.txt file optimization"])
    report["Source"].append(sources["Robots.txt file optimization"])
    report["Status"].append("✅ Pass" if robots_success else "ℹ️ Not Available")

    report["Category"].append("Crawling & Indexing")
    report["Parameters"].append("Sitemap file optimization")
    report["Current Value"].append("Available" if sitemap_success else "N/A")
    report["Expected Value"].append(expected_outcomes["Sitemap file optimization"])
    report["Source"].append(sources["Sitemap file optimization"])
    report["Status"].append("✅ Pass" if sitemap_success else "ℹ️ Not Available")

    # Site Health & Structure
    broken_internal_links = len(df[df["Status Code"] == 404])
    report["Category"].append("Site Health & Structure")
    report["Parameters"].append("Broken internal links (404)")
    report["Current Value"].append(broken_internal_links)
    report["Expected Value"].append(expected_outcomes["Broken internal links (404)"])
    report["Source"].append(sources["Broken internal links (404)"])
    report["Status"].append("❌ Fail" if broken_internal_links > 0 else "✅ Pass")

    report["Category"].append("Site Health & Structure")
    report["Parameters"].append("Broken external links")
    report["Current Value"].append("N/A")
    report["Expected Value"].append(expected_outcomes["Broken external links"])
    report["Source"].append(sources["Broken external links"])
    report["Status"].append("ℹ️ Not Available")

    report["Category"].append("Site Health & Structure")
    report["Parameters"].append("Broken backlinks")
    report["Current Value"].append("N/A")
    report["Expected Value"].append(expected_outcomes["Broken backlinks"])
    report["Source"].append(sources["Broken backlinks"])
    report["Status"].append("ℹ️ Not Available")

    report["Category"].append("Site Health & Structure")
    report["Parameters"].append("Broken Images")
    report["Current Value"].append("N/A")
    report["Expected Value"].append(expected_outcomes["Broken Images"])
    report["Source"].append(sources["Broken Images"])
    report["Status"].append("ℹ️ Not Available")

    orphan_pages_count = 0
    if orphan_pages_df is not None and not orphan_pages_df.empty:
        orphan_pages_count = len(orphan_pages_df)
    report["Category"].append("Site Health & Structure")
    report["Parameters"].append("Orphan page")
    report["Current Value"].append(orphan_pages_count)
    report["Expected Value"].append(expected_outcomes["Orphan page"])
    report["Source"].append(sources["Orphan page"])
    report["Status"].append("❌ Fail" if orphan_pages_count > 0 else "✅ Pass")

    canonical_errors = len(df[df["Canonical Link Element 1"] != df["Address"]])
    report["Category"].append("Site Health & Structure")
    report["Parameters"].append("Canonical Errors")
    report["Current Value"].append(canonical_errors)
    report["Expected Value"].append(expected_outcomes["Canonical Errors"])
    report["Source"].append(sources["Canonical Errors"])
    report["Status"].append("❌ Fail" if canonical_errors > 0 else "✅ Pass")

    report["Category"].append("Site Health & Structure")
    report["Parameters"].append("Information architecture")
    report["Current Value"].append("N/A")
    report["Expected Value"].append(expected_outcomes["Information architecture"])
    report["Source"].append(sources["Information architecture"])
    report["Status"].append("ℹ️ Not Available")

    report["Category"].append("Site Health & Structure")
    report["Parameters"].append("Header tags structure")
    report["Current Value"].append("N/A")
    report["Expected Value"].append(expected_outcomes["Header tags structure"])
    report["Source"].append(sources["Header tags structure"])
    report["Status"].append("ℹ️ Not Available")

    link_profile_metrics = ["Backlinks", "Domain authority", "Spam Score"]
    for metric in link_profile_metrics:
        report["Category"].append("Link Profile & Authority")
        report["Parameters"].append(metric)
        report["Current Value"].append("N/A")
        report["Expected Value"].append(expected_outcomes[metric])
        report["Source"].append(sources[metric])
        report["Status"].append("ℹ️ Not Available")

    duplicate_content = 0
    if "Word Count" in df.columns and "Sentence Count" in df.columns:
        df_content = df[
            df["Word Count"].notna() & df["Sentence Count"].notna() & ~((df["Word Count"] == 0) & (df["Sentence Count"] == 0))
        ]   
        duplicate_content = len(
            df_content[
                df_content.duplicated(
                    subset=["Word Count", "Sentence Count"], keep=False
                )
            ]
        )
    report["Category"].append("Metadata & Schema")
    report["Parameters"].append("Duplicate content")
    report["Current Value"].append(duplicate_content)
    report["Expected Value"].append(expected_outcomes["Duplicate content"])
    report["Source"].append(sources["Duplicate content"])
    report["Status"].append("❌ Fail" if duplicate_content > 0 else "✅ Pass")

    images_missing_alt_text = 0
    if alt_tag_df is not None and not alt_tag_df.empty:
        images_missing_alt_text = len(alt_tag_df)
    report["Category"].append("Metadata & Schema")
    report["Parameters"].append("Img alt tag")
    report["Current Value"].append(images_missing_alt_text)
    report["Expected Value"].append(expected_outcomes["Img alt tag"])
    report["Source"].append(sources["Img alt tag"])
    report["Status"].append("❌ Fail" if images_missing_alt_text > 0 else "✅ Pass")

    missing_h1 = df["H1-1"].isna().sum()
    duplicate_h1 = len(df[df["H1-1"].duplicated(keep=False)])
    report["Category"].append("Metadata & Schema")
    report["Parameters"].append("Duplicate & missing H1")
    report["Current Value"].append(f"Missing: {missing_h1}, Duplicate: {duplicate_h1}")
    report["Expected Value"].append(expected_outcomes["Duplicate & missing H1"])
    report["Source"].append(sources["Duplicate & missing H1"])
    report["Status"].append(
        "❌ Fail" if missing_h1 > 0 or duplicate_h1 > 0 else "✅ Pass"
    )

    missing_title = df["Title 1"].isna().sum()
    duplicate_titles = 0
    df_with_titles = df[df["Title 1"].notna() & (df["Title 1"] != "")]
    duplicate_titles = len(
        df_with_titles[df_with_titles["Title 1"].duplicated(keep=False)]
    )
    report["Category"].append("Metadata & Schema")
    report["Parameters"].append("Duplicate & missing meta title")
    report["Current Value"].append(
        f"Missing: {missing_title}, Duplicate: {duplicate_titles}"
    )
    report["Expected Value"].append(expected_outcomes["Duplicate & missing meta title"])
    report["Source"].append(sources["Duplicate & missing meta title"])
    report["Status"].append(
        "❌ Fail" if missing_title > 0 or duplicate_titles > 0 else "✅ Pass"
    )

    missing_description = df["Meta Description 1"].isna().sum()
    duplicate_descriptions = len(df[df["Meta Description 1"].duplicated(keep=False)])
    report["Category"].append("Metadata & Schema")
    report["Parameters"].append("Duplicate & missing description")
    report["Current Value"].append(
        f"Missing: {missing_description}, Duplicate: {duplicate_descriptions}"
    )
    report["Expected Value"].append(
        expected_outcomes["Duplicate & missing description"]
    )
    report["Source"].append(sources["Duplicate & missing description"])
    report["Status"].append(
        "❌ Fail"
        if missing_description > 0 or duplicate_descriptions > 0
        else "✅ Pass"
    )
    update_schema_markup_analysis(df, report, expected_outcomes, sources)

    duplicate_data = None
    if duplicate_titles > 0:
        duplicate_data = df_with_titles[
            df_with_titles["Title 1"].duplicated(keep=False)
        ][["Address", "Title 1", "Title 1 Length"]]

    duplicate_content_data = None
    if (
        duplicate_content > 0
        and "Word Count" in df.columns
        and "Sentence Count" in df.columns
    ):
        duplicate_content_data = df[
            df["Word Count"].notna() & df["Sentence Count"].notna() & ~((df["Word Count"] == 0) & (df["Sentence Count"] == 0))
        ]
        duplicate_content_data = duplicate_content_data[
            duplicate_content_data.duplicated(subset=["Word Count", "Sentence Count"], keep=False)
        ][["Address", "Word Count", "Sentence Count"]]

    h1_issues_data = None
    if missing_h1 > 0 or duplicate_h1 > 0:
        h1_issues_data = df[df["H1-1"].isna() | df["H1-1"].duplicated(keep=False)][
            ["Address", "H1-1"]
        ]
        h1_issues_data = h1_issues_data[h1_issues_data["Address"].apply(is_valid_page_url)]

    description_issues_data = None
    if missing_description > 0 or duplicate_descriptions > 0:
        description_issues_data = df[
            df["Meta Description 1"].isna()
            | df["Meta Description 1"].duplicated(keep=False)
        ][["Address", "Meta Description 1"]]
        description_issues_data = description_issues_data[description_issues_data["Address"].apply(is_valid_page_url)]

    final_report_df = pd.DataFrame(report)
    if not final_report_df.empty:
        final_report_df = final_report_df.set_index(["Category", "Parameters"])

    return final_report_df, {
        "duplicate_titles": duplicate_data,
        "duplicate_content": duplicate_content_data,
        "h1_issues": h1_issues_data,
        "description_issues": description_issues_data,
    }


def detect_url_language(url):
    parsed_url = urlparse(url)
    path = parsed_url.path.lower()
    hostname = parsed_url.hostname.lower() if parsed_url.hostname else ''

    language = None
    category = None

    country_lang_map = {
        '.cn': 'zh',    # China
        '.jp': 'ja',    # Japan
        '.kr': 'ko',    # Korea
        '.tw': 'zh',    # Taiwan
        '.hk': 'zh',    # Hong Kong
        '.it': 'it',    # Italy
        '.es': 'es',    # Spain
        '.fr': 'fr',    # France
        '.de': 'de',    # Germany
        '.pt': 'pt',    # Portugal
        '.nl': 'nl',    # Netherlands
        '.pl': 'pl',    # Poland
        '.se': 'sv',    # Sweden
        '.no': 'no',    # Norway
        '.fi': 'fi',    # Finland
        '.dk': 'da',    # Denmark
        '.cz': 'cs',    # Czech Republic
        '.hu': 'hu',    # Hungary
        '.ro': 'ro',    # Romania
        '.hr': 'hr',    # Croatia
        '.rs': 'sr',    # Serbia
        '.bg': 'bg',    # Bulgaria
        '.sk': 'sk',    # Slovakia
        '.si': 'sl'     # Slovenia
    }

    language_patterns = {
        'en': [r'/en/', r'/en-', r'/english/', r'/us/', r'/uk/', r'/au/', r'/international/'],
        'it': [r'/it/', r'/it-', r'/italiano/', r'/italian/', r'/ch/'],
        'es': [r'/es/', r'/es-', r'/espanol/', r'/spanish/', r'/mx/', r'/cl/', r'/co/', r'/latam/'],
        'fr': [r'/fr/', r'/fr-', r'/french/', r'/ca/', r'/ch/', r'/be/'],
        'de': [r'/de/', r'/de-', r'/deutsch/', r'/german/', r'/at/', r'/ch/'],
        'pt': [r'/pt/', r'/pt-', r'/portuguese/', r'/br/', r'/pt/', r'/ao/'],
        'ru': [r'/ru/', r'/ru-', r'/russian/', r'/by/', r'/kz/'],
        'nl': [r'/nl/', r'/nl-', r'/dutch/', r'/netherlands/'],
        'vi': [r'/vi/', r'/vi-', r'/vietnamese/'],
        'pl': [r'/pl/', r'/pl-', r'/polish/'],
        'hu': [r'/hu/', r'/hu-', r'/hungarian/'],
        'tr': [r'/tr/', r'/tr-', r'/turkish/'],
        'th': [r'/th/', r'/th-', r'/thai/'],
        'cs': [r'/cs/', r'/cs-', r'/czech/'],
        'el': [r'/el/', r'/el-', r'/greek/'],
        'ja': [r'/ja/', r'/ja-', r'/japanese/', r'/jp/'],
        'zh': [r'/zh/', r'/zh-', r'/zhs/', r'/chinese/', r'/cn/', r'/hk/', r'/tw/', r'/zh-cn/', r'/zh-tw/', r'/zh-hk/', r'/zht/'],
        'ko': [r'/ko/', r'/ko-', r'/korean/', r'/kr/'],
        'ar': [r'/ar/', r'/ar-', r'/arabic/', r'/sa/', r'/ae/'],
    }

    category_patterns = {
        'blogs': [r'/blogs/', r'/blogs-', r'/en/blogs/', r'/blog/',r'/insights/'],
        'corporate': [r'/corporate/', r'/corporate-', r'/en/corporate/', r'/corp/'],
        'how-to': [r'/how-to/', r'/how-to-', r'/en/how-to/', r'/howto/'],
        'products': [r'/products/', r'/products-'],
        'resources': [r'/resources/', r'/resources-'],
        'company': [r'/company/', r'/company-'],
        'partners': [r'/partners/', r'/partners-'],
        'solutions': [r'/solutions/', r'/solutions-'],
        'support': [r'/support/', r'/help/', r'/faq/'],
        'about': [r'/about/', r'/about-us/'],
        'contact': [r'/contact/', r'/contact-us/'],
        'news': [r'/news/', r'/press/'],
        'careers': [r'/careers/', r'/jobs/'],
        'legal': [r'/legal/', r'/privacy/', r'/terms/'],
    }

    specific_domain_patterns = {
        'zh': [r'teamviewer\.cn', r'teamviewer\.com\.cn'],
        'ja': [r'teamviewer\.com/ja'],
        'it': [r'teamviewer\.com/it'],
        'es': [r'teamviewer\.com/latam']
    }

    for lang, patterns in specific_domain_patterns.items():
        if any(re.search(pattern, url, re.IGNORECASE) for pattern in patterns):
            language = lang
            break

    if not language:
        for domain_suffix, lang in country_lang_map.items():
            if hostname.endswith(domain_suffix):
                language = lang
                break

    path_parts = path.split('/')
    
    # Check for language identifiers
    for lang, patterns in language_patterns.items():
        for pattern in patterns:
            clean_pattern = pattern.strip('/')
            if clean_pattern in path_parts:
                language = lang
                break
        if language:
            break
        
    for cat, patterns in category_patterns.items():
        for pattern in patterns:
            clean_pattern = pattern.strip('/')
            if clean_pattern in path_parts:
                category = cat
                break
        if category:
            break

    if not language and parsed_url.query:
        lang_param = re.search(r'(?:^|&)lang=([a-zA-Z]{2})', parsed_url.query)
        if lang_param and lang_param.group(1).lower() in language_patterns:
            language = lang_param.group(1).lower()

    product_lang_patterns = {
        'es': [r'/distribucion-de-licencias-tensor'],
        'zh': [r'/anydesk\.com/zhs/solutions/']
    }

    if not language:
        for lang, patterns in product_lang_patterns.items():
            if any(re.search(pattern, url, re.IGNORECASE) for pattern in patterns):
                language = lang
                break

    if not language:
        language = 'en'

    return language, category

def fetch_sitemap_urls(website_url):
    sitemap_paths = ["/sitemap.xml", "/sitemap_index.xml", "/sitemap-1.xml", "/sitemaps/sitemap.xml", "/sitemaps/sitemap_index.xml"]
    base_url = website_url.rstrip('/')
    all_urls = set() 
    processed_sitemaps = set()

    for path in sitemap_paths:
        sitemap_url = base_url + path
        if sitemap_url in processed_sitemaps:
            continue
            
        try:
            response = requests.get(sitemap_url, timeout=10, headers={'User-Agent': 'Mozilla/5.0'}, verify=False)
            if response.status_code == 200:
                processed_sitemaps.add(sitemap_url)
                sitemap_urls = parse_sitemap_index(response.text, base_url, processed_sitemaps)
                if not sitemap_urls:
                    sitemap_urls = parse_sitemap(response.text)
                all_urls.update(sitemap_urls)  # Use update to add to set
                logger.info(f"Successfully parsed sitemap: {sitemap_url}")
        except requests.exceptions.RequestException as e:
            logger.warning(f"Failed to fetch sitemap {sitemap_url}: {e}")
            continue
    
    return list(all_urls) 

def parse_sitemap_index(sitemap_content, base_url, processed_sitemaps=None):
    if processed_sitemaps is None:
        processed_sitemaps = set()
        
    all_urls = set()
    
    try:
        soup = BeautifulSoup(sitemap_content, 'lxml-xml')
        sitemap_tags = soup.find_all('sitemap')
        
        for sitemap in sitemap_tags:
            loc = sitemap.find('loc')
            if loc:
                nested_sitemap_url = loc.get_text().strip()
                if not nested_sitemap_url.startswith('http'):
                    nested_sitemap_url = urljoin(base_url, nested_sitemap_url)
                
                if nested_sitemap_url in processed_sitemaps:
                    continue
                    
                try:
                    processed_sitemaps.add(nested_sitemap_url)
                    nested_response = requests.get(nested_sitemap_url, timeout=10, headers={'User-Agent': 'Mozilla/5.0'}, verify=False)
                    if nested_response.status_code == 200:
                        nested_soup = BeautifulSoup(nested_response.text, 'lxml-xml')
                        if nested_soup.find_all('sitemap'):
                            nested_urls = parse_sitemap_index(nested_response.text, base_url, processed_sitemaps)
                        else:
                            nested_urls = parse_sitemap(nested_response.text)
                        all_urls.update(nested_urls)
                except requests.exceptions.RequestException as e:
                    logger.warning(f"Failed to fetch nested sitemap {nested_sitemap_url}: {e}")
                    continue
    except Exception as e:
        logger.error(f"Error parsing sitemap index: {e}")
        
    return list(all_urls)

def parse_sitemap(sitemap_content):
    urls = set() 
    image_extensions = {'.png', '.jpg', '.jpeg', '.gif', '.bmp', '.webp', '.svg', '.tiff', '.ico'}
    
    try:
        soup = BeautifulSoup(sitemap_content, 'lxml-xml')
        loc_tags = soup.find_all('loc')
        for tag in loc_tags:
            url = tag.get_text().strip()
            if any(url.lower().endswith(ext) for ext in image_extensions):
                continue
            if url:
                urls.add(url)
    except Exception as e:
        logger.error(f"Error parsing sitemap: {e}")
        
    return list(urls)

def analyze_sitemap_categories(urls):
    category_counts = Counter()
    language_counts = Counter()
    categorized_urls = []
    
    for url in urls:
        language, category = detect_url_language(url)
        if category:
            category_counts[category] += 1
        language_counts[language] += 1
        categorized_urls.append({
            'URL': url,
            'Language': language,
            'Category': category if category else 'Other'
        })
    
    return category_counts, language_counts, categorized_urls
