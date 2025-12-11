import streamlit as st
import pandas as pd
import os
from pathlib import Path
from collections import Counter
import requests
import logging
from urllib3.exceptions import InsecureRequestWarning
from urllib.parse import urlparse, parse_qs
from modules.helper_function import*

requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

BASE_DIR = Path(__file__).parent

DATA_FILE_PATH = BASE_DIR / "Data" / "internal_html_efax.csv"
ALT_TAG_DATA_PATH = BASE_DIR / "Data" / "images_missing_alt_text.csv"
ORPHAN_PAGES_DATA_PATH = BASE_DIR / "Data" / "analytics_orphan_urls.csv"

def filter_pages(df, include_query_params=False, custom_exclusions=None):
    original_count = len(df)
    
    default_exclusions = {
        '.pdf', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx',
        '.zip', '.rar', '.tar', '.gz', '.7z',
        '.jpg', '.jpeg', '.png', '.gif', '.svg', '.webp', '.ico', '.bmp',
        '.mp4', '.avi', '.mov', '.wmv', '.flv', '.webm', '.mp3', '.wav', '.ogg',
        '.css', '.js', '.xml', '.json', '.txt', '.csv',
        '.woff', '.woff2', '.ttf', '.eot', '.otf'
    }
    
    if custom_exclusions:
        default_exclusions.update(custom_exclusions)
    
    filtered_df = df.copy()
    
    filter_stats = {
        'original_count': original_count,
        'excluded_extensions': 0,
        'excluded_query_params': 0,
        'excluded_fragments': 0,
        'final_count': 0
    }
    
    extension_mask = filtered_df['Address'].str.lower().str.contains(
        '|'.join([f'\\{ext}' for ext in default_exclusions]), 
        regex=True, 
        na=False
    )
    excluded_by_extension = filtered_df[extension_mask]
    filter_stats['excluded_extensions'] = len(excluded_by_extension)
    filtered_df = filtered_df[~extension_mask]

    if not include_query_params:
        query_mask = filtered_df['Address'].str.contains(r'\?', regex=True, na=False)
        excluded_by_query = filtered_df[query_mask]
        filter_stats['excluded_query_params'] = len(excluded_by_query)
        filtered_df = filtered_df[~query_mask]
    
    fragment_mask = filtered_df['Address'].str.contains(r'#', regex=True, na=False)
    excluded_by_fragment = filtered_df[fragment_mask]
    filter_stats['excluded_fragments'] = len(excluded_by_fragment)
    filtered_df = filtered_df[~fragment_mask]
    
    api_mask = filtered_df['Address'].str.contains(r'/api/|/ajax/|/json/|\.json|\.xml', regex=True, na=False)
    excluded_by_api = filtered_df[api_mask]
    filter_stats['excluded_api'] = len(excluded_by_api)
    filtered_df = filtered_df[~api_mask]
    
    admin_mask = filtered_df['Address'].str.contains(r'/admin/|/wp-admin/|/administrator/|/backend/', regex=True, na=False)
    excluded_by_admin = filtered_df[admin_mask]
    filter_stats['excluded_admin'] = len(excluded_by_admin)
    filtered_df = filtered_df[~admin_mask]
    
    filter_stats['final_count'] = len(filtered_df)
    
    return filtered_df, filter_stats

def display_filter_summary(filter_stats):
    """Display filtering summary in Streamlit"""
    st.subheader("🔍 Page Filtering Summary")
    
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        st.metric(
            "Original Pages",
            f"{filter_stats['original_count']:,}",
            help="Total pages in Screaming Frog export"
        )
    
    with col2:
        st.metric(
            "Filtered Pages",
            f"{filter_stats['final_count']:,}",
            help="Pages after filtering non-HTML content"
        )
    
    with col3:
        excluded_total = (filter_stats['original_count'] - filter_stats['final_count'])
        st.metric(
            "Excluded Pages",
            f"{excluded_total:,}",
            help="Total pages excluded from analysis"
        )
    
    with col4:
        retention_rate = (filter_stats['final_count'] / filter_stats['original_count']) * 100
        st.metric(
            "Retention Rate",
            f"{retention_rate:.1f}%",
            help="Percentage of pages kept after filtering"
        )
    
    # Detailed breakdown
    with st.expander("📊 Detailed Filtering Breakdown"):
        breakdown_data = {
            'Filter Type': [
                'File Extensions (.pdf, .png, etc.)',
                'Query Parameters (?q=, etc.)',
                'URL Fragments (#section)',
                'API Endpoints',
                'Admin/Backend URLs'
            ],
            'Pages Excluded': [
                filter_stats.get('excluded_extensions', 0),
                filter_stats.get('excluded_query_params', 0),
                filter_stats.get('excluded_fragments', 0),
                filter_stats.get('excluded_api', 0),
                filter_stats.get('excluded_admin', 0)
            ]
        }
        
        breakdown_df = pd.DataFrame(breakdown_data)
        st.dataframe(breakdown_df, use_container_width=True, hide_index=True)

def display_summary_cards(domain, total_pages, category_counts, language_counts):
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        st.metric(
            label="🌐 Domain",
            value=domain,
            help="The website domain being analyzed"
        )
    
    with col2:
        st.metric(
            label="📄 Total Pages",
            value=f"{total_pages:,}",
            help="Total number of pages found in sitemap"
        )
    
    with col3:
        categories_count = len(category_counts)
        st.metric(
            label="📂 Categories",
            value=categories_count,
            help="Number of different page categories identified"
        )
    
    with col4:
        languages_count = len(language_counts)
        st.metric(
            label="🌍 Languages",
            value=languages_count,
            help="Number of different languages detected"
        )

def main():
    st.set_page_config(page_title="Web Audit Data Analyzer", layout="wide")

    st.title("🔍 Web Audit Data Analyzer")
    st.markdown(
        "A comprehensive analysis of your website's SEO health based on Screaming Frog data and sitemap analysis"
    )
    st.divider()

    try:
        file_option = st.radio(
            "Select data source", ["Use default file path", "Upload files"]
        )

        df = None
        alt_tag_df = None
        orphan_pages_df = None

        if file_option == "Upload files":
            st.info("You must upload all three files to proceed with the analysis")

            col1, col2, col3 = st.columns(3)

            with col1:
                st.markdown("### Main Screaming Frog Data")
                main_file = st.file_uploader(
                    "Upload Screaming Frog CSV or Excel export", 
                    type=["csv", "xls", "xlsx"], 
                    key="main_file"
                )
                if main_file:
                    if main_file.name.endswith(".csv"):
                        df = pd.read_csv(main_file)
                    else:
                        df = pd.read_excel(main_file)
                    st.success(f"✅ Main file uploaded with {len(df)} rows")
                else:
                    st.warning("Main file required")

            with col2:
                st.markdown("### Alt Tag Data")
                alt_tag_file = st.file_uploader(
                    "Upload Images Missing Alt Tags CSV or Excel", 
                    type=["csv", "xls", "xlsx"], 
                    key="alt_tag_file"
                )
                if alt_tag_file:
                    if alt_tag_file.name.endswith(".csv"):
                        alt_tag_df = pd.read_csv(alt_tag_file)
                    else:
                        alt_tag_df = pd.read_excel(alt_tag_file)
                    st.success(f"✅ Alt tag file uploaded with {len(alt_tag_df)} rows")
                else:
                    st.warning("Alt tag file required")

            with col3:
                st.markdown("### Orphan Pages Data")
                orphan_file = st.file_uploader(
                    "Upload Orphan Pages CSV or Excel", 
                    type=["csv", "xls", "xlsx"], 
                    key="orphan_file"
                )
                if orphan_file:
                    if orphan_file.name.endswith(".csv"):
                        orphan_pages_df = pd.read_csv(orphan_file)
                    else:
                        orphan_pages_df = pd.read_excel(orphan_file)
                    st.success(
                        f"✅ Orphan pages file uploaded with {len(orphan_pages_df)} rows"
                    )
                else:
                    st.warning("Orphan pages file required")

            all_files_uploaded = (
                main_file is not None
                and alt_tag_file is not None
                and orphan_file is not None
            )

            if not all_files_uploaded:
                st.warning("Please upload all three required files to continue")
                return

        else:
            if (
                os.path.exists(DATA_FILE_PATH)
                and os.path.exists(ALT_TAG_DATA_PATH)
                and os.path.exists(ORPHAN_PAGES_DATA_PATH)
            ):
                df = pd.read_csv(DATA_FILE_PATH)
                alt_tag_df = pd.read_csv(ALT_TAG_DATA_PATH)
                orphan_pages_df = pd.read_csv(ORPHAN_PAGES_DATA_PATH)
            else:
                missing_files = []
                if not os.path.exists(DATA_FILE_PATH):
                    missing_files.append(f"Main data file: {DATA_FILE_PATH}")
                if not os.path.exists(ALT_TAG_DATA_PATH):
                    missing_files.append(f"Alt tag data file: {ALT_TAG_DATA_PATH}")
                if not os.path.exists(ORPHAN_PAGES_DATA_PATH):
                    missing_files.append(
                        f"Orphan pages data file: {ORPHAN_PAGES_DATA_PATH}"
                    )

                st.error("The following files were not found at the default paths:")
                for file in missing_files:
                    st.error(f"- {file}")
                st.error("Please use the 'Upload files' option instead.")
                return

        st.divider()

        if st.button("🚀 Generate Web Audit Report", type="primary", use_container_width=True):
            
            if df is not None and len(df) > 0:
                # Apply filtering to main dataset
                if 'Address' in df.columns:
                    filtered_df, filter_stats = filter_pages(
                        df, 
                        include_query_params=False,
                        custom_exclusions=None
                    )
                    
                    # Display filtering summary
                    display_filter_summary(filter_stats)
                    st.markdown("---")
                    
                    # Use filtered data for analysis
                    df_for_analysis = filtered_df
                else:
                    st.warning("'Address' column not found in main data. Proceeding without filtering.")
                    df_for_analysis = df
                    filter_stats = {'final_count': len(df)}
                
                domain = (
                    df_for_analysis["Address"].iloc[0].split("/")[2]
                    if "://" in df_for_analysis["Address"].iloc[0]
                    else df_for_analysis["Address"].iloc[0]
                )
                website_url = f"https://{domain}" if not domain.startswith('http') else domain
                
                progress_bar = st.progress(0)
                status_text = st.empty()
                
                status_text.text("🔍 Analyzing sitemap...")
                progress_bar.progress(20)
                
                try:
                    sitemap_urls = fetch_sitemap_urls(website_url)
                    if sitemap_urls:
                        unique_count = len(set(sitemap_urls))
                        total_count = len(sitemap_urls)
                        logger.info(f"Found {total_count} total URLs, {unique_count} unique URLs")
                        
                        category_counts, language_counts, categorized_urls = analyze_sitemap_categories(sitemap_urls)
                        sitemap_success = True
                    else:
                        category_counts, language_counts, categorized_urls = Counter(), Counter(), []
                        sitemap_success = False
                except Exception as e:
                    category_counts, language_counts, categorized_urls = Counter(), Counter(), []
                    sitemap_success = False
                    st.error(f"Error analyzing sitemap: {str(e)}")
                
                progress_bar.progress(40)
                
                status_text.text("📊 Generating SEO analysis...")
                progress_bar.progress(60)
                
                # Check for robots.txt existence
                robots_url = website_url.rstrip('/') + '/robots.txt'
                try:
                    robots_response = requests.get(robots_url, timeout=5, headers={'User-Agent': 'Mozilla/5.0'}, verify=False)
                    robots_success = robots_response.status_code == 200
                except Exception:
                    robots_success = False
                # Use filtered data for SEO analysis
                report_df, detailed_data = analyze_screaming_frog_data(
                    df_for_analysis, alt_tag_df, orphan_pages_df, sitemap_success=sitemap_success, robots_success=robots_success
                )
                
                progress_bar.progress(80)
                status_text.text("📋 Preparing tables...")
                
                progress_bar.progress(100)
                status_text.text("✅ Analysis complete!")
                
                progress_bar.empty()
                status_text.empty()
                
                st.success(f"🌐 Complete audit report for: **{domain}** (Analyzed {filter_stats['final_count']:,} pages)")
                
                st.header("📊 Website Overview")
                
                if sitemap_success and sitemap_urls:
                    display_summary_cards(domain, len(sitemap_urls), category_counts, language_counts)
                    
                    st.markdown("---")
                    table_col1, table_col2 = st.columns(2)
                    
                    with table_col1:
                        if category_counts:
                            st.subheader("📂 Category Breakdown")
                            cat_summary = pd.DataFrame([
                                {"Category": cat.title(), "Page Count": count}
                                for cat, count in category_counts.most_common()
                            ])
                            
                            st.dataframe(
                                cat_summary,
                                use_container_width=True,
                                hide_index=True,
                                column_config={
                                    "Category": st.column_config.TextColumn("Category", width="medium"),
                                    "Page Count": st.column_config.NumberColumn("Page Count", width="small"),
                                }
                            )
                    
                    with table_col2:
                        if language_counts:
                            st.subheader("🌍 Language Breakdown")
                            lang_summary = pd.DataFrame([
                                {"Language": lang.upper(), "Page Count": count}
                                for lang, count in language_counts.most_common()
                            ])
                            
                            st.dataframe(
                                lang_summary,
                                use_container_width=True,
                                hide_index=True,
                                column_config={
                                    "Language": st.column_config.TextColumn("Language", width="medium"),
                                    "Page Count": st.column_config.NumberColumn("Page Count", width="small")
                                }
                            )
                    
                else:
                    st.warning("⚠️ Sitemap analysis failed or no URLs found in sitemap")
                    display_summary_cards(domain, len(df_for_analysis), Counter(), Counter())
                
                st.markdown("---")
                
                st.header("SEO Audit Results")
                
                def highlight_status(val):
                    if val == "✅ Pass":
                        return "background-color: #28a745; color: white;"
                    elif val == "❌ Fail":
                        return "background-color: #dc3545; color: white;"
                    elif val == "ℹ️ Review":
                        return "background-color: #ffc107; color: black;"
                    elif val == "ℹ️ Not Available":
                        return "background-color: #D3D3D3; color: black;"
                    else:
                        return ""

                if not report_df.empty:
                    styled_df = report_df.style.applymap(
                        highlight_status,
                        subset=["Status"]
                    )
                    st.dataframe(styled_df, use_container_width=True)
                else:
                    st.info("No SEO report data to display.")
                
                st.markdown("---")
                
                st.header("🔍 Detailed Analysis")
                
                detailed_tabs = [
                    key for key, value in detailed_data.items()
                    if value is not None and not value.empty
                ]

                if detailed_tabs:
                    tabs = st.tabs([name.replace("_", " ").title() for name in detailed_tabs])
                    
                    for i, tab_name in enumerate(detailed_tabs):
                        with tabs[i]:
                            st.dataframe(detailed_data[tab_name], use_container_width=True)

                col1, col2 = st.columns(2)
                
                with col1:
                    if alt_tag_df is not None and not alt_tag_df.empty:
                        st.subheader("Images Missing Alt Text")
                        st.info(f"Found {len(alt_tag_df)} images missing alt text")
                        with st.expander("View Details", expanded=False):
                            st.dataframe(alt_tag_df, use_container_width=True)

                with col2:
                    if orphan_pages_df is not None and not orphan_pages_df.empty:
                        st.subheader("Orphan Pages")
                        st.info(f"Found {len(orphan_pages_df)} orphan pages")
                        with st.expander("View Details", expanded=False):
                            st.dataframe(orphan_pages_df, use_container_width=True)
                
                st.markdown("---")
                
                st.header("💾 Download Reports")
                
                download_col1, download_col2, download_col3 = st.columns(3)
                
                with download_col1:
                    if not report_df.empty:
                        export_df = report_df.reset_index()
                        export_df["Status"] = export_df["Status"].replace({
                            "✅ Pass": "Pass",
                            "❌ Fail": "Fail", 
                            "ℹ️ Review": "Review",
                            "ℹ️ Not Available": "Not Available",
                        })
                        csv = export_df.to_csv(index=False)
                        st.download_button(
                            label="Download SEO Report",
                            data=csv.encode("utf-8"),
                            file_name=f"{domain}_seo_audit_report.csv",
                            mime="text/csv",
                            use_container_width=True
                        )

                with download_col2:
                    if sitemap_success and categorized_urls:
                        categorized_df = pd.DataFrame(categorized_urls)
                        csv_data = categorized_df.to_csv(index=False)
                        st.download_button(
                            label="Download URL Categories",
                            data=csv_data.encode('utf-8'),
                            file_name=f"{domain}_categorized_urls.csv",
                            mime="text/csv",
                            use_container_width=True
                        )

                with download_col3:
                    summary_data = {
                        'Metric': [
                            'Domain', 
                            'Total Pages (Sitemap)', 
                            'Total Pages (Crawled - Original)', 
                            'Total Pages (Crawled - Filtered)',
                            'Languages Detected', 
                            'Categories Detected'
                        ],
                        'Value': [
                            domain,
                            len(sitemap_urls) if sitemap_success else 'N/A',
                            len(df),
                            filter_stats['final_count'],
                            len(language_counts) if language_counts else 'N/A',
                            len(category_counts) if category_counts else 'N/A'
                        ]
                    }
                    summary_df = pd.DataFrame(summary_data)
                    summary_csv = summary_df.to_csv(index=False)
                    st.download_button(
                        label="📋 Download Summary",
                        data=summary_csv.encode('utf-8'),
                        file_name=f"{domain}_audit_summary.csv",
                        mime="text/csv",
                        use_container_width=True
                    )
                    
        with st.expander("Preview Raw Data", expanded=False):
            tabs = st.tabs(["Main Data", "Alt Tag Data", "Orphan Pages Data"])

            with tabs[0]:
                if df is not None:
                    st.info(f"Showing first 100 rows of {len(df)} total rows")
                    st.dataframe(df.head(100), use_container_width=True)

            with tabs[1]:
                if alt_tag_df is not None:
                    st.info(f"Showing first 100 rows of {len(alt_tag_df)} total rows")
                    st.dataframe(alt_tag_df.head(100), use_container_width=True)
                else:
                    st.warning("Alt tag data not loaded")

            with tabs[2]:
                if orphan_pages_df is not None:
                    st.info(f"Showing first 100 rows of {len(orphan_pages_df)} total rows")
                    st.dataframe(orphan_pages_df.head(100), use_container_width=True)
                else:
                    st.warning("Orphan pages data not loaded")

    except Exception as e:
        st.error(f"❌ An error occurred: {str(e)}")
        st.error("Please make sure your files are in the correct format and try again.")
        
if __name__ == "__main__":
    main()  