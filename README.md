# Web Audit Data Analyzer

A Python-based tool built with Streamlit for analyzing website SEO health and header structure. The application provides comprehensive analysis of SEO metrics, header hierarchy, and content duplication.

## Features

### SEO Health Check
- **Technical Health Analysis**
  - Broken internal links detection
  - Canonical tag verification
  - Indexability status monitoring
- **Content Analysis**
  - Duplicate title detection
  - Meta description analysis
  - H1 tag verification
- Detailed reporting with downloadable CSV exports

### Header Analysis
- Real-time header structure analysis
- Multi-threaded URL processing
- SEO issues detection:
  - Missing H1 tags
  - Duplicate H1 tags
  - Header hierarchy issues
- Visual analytics with progress tracking

## Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/yourusername/web-audit-data-analyzer.git
   cd web-audit-data-analyzer

2. Create and activate the virtual environment:
   ```bash
    python -m venv .venv
    source ./.venv/bin/activate

3. Install dependencies using uv:
   ```bash
   uv sync

All dependencies are managed via uv just run uv sync after cloning and activating your virtual environment.

## Usage
Place your CSV data file in the Data/ directory.

Update the DATA_FILE_PATH constant in app1.py if your file is named differently or located elsewhere.

Run the Streamlit app:
  ```bash
streamlit run app1.py


