# Reproduction Guide

This guide provides step-by-step instructions for reproducing the vendor-specific CWE analysis research. The analysis can be performed using either parquet files or a DuckDB database file.

!!! abstract "Reproduction Overview"
    **Goal**: Reproduce the comprehensive analysis of 50,270 CVEs across 733 unique CWEs for five major technology vendors.
    
    **Expected Time**: 2-4 hours (depending on data source and system performance)
    
    **Skill Level**: Intermediate Python, basic SQL knowledge recommended

## 🖥️ System Requirements

### Minimum Requirements
!!! warning "Hardware Specifications"
    - **RAM**: 8GB minimum, 16GB recommended
    - **Storage**: 10GB available space for data and outputs
    - **CPU**: Multi-core processor recommended for large dataset processing
    - **OS**: Windows 10+, macOS 10.14+, or Linux (Ubuntu 18.04+)

### Software Dependencies
!!! note "Required Software"
    - **Python 3.8+** with pip package manager
    - **Jupyter Lab/Notebook** for interactive analysis
    - **Git** for repository management (optional)

## 📥 Data Setup Options

You have two options for accessing the research data:

=== "Option 1: Parquet Files (Recommended)"

    !!! tip "Using Parquet Files"
        This is the original research approach, offering maximum flexibility and transparency.
        
        **Advantages:**
        - Full transparency of data processing steps
        - Ability to modify queries and analysis
        - Individual table access for targeted analysis
        - Compatible with various analytics tools
        
        **Data Files Required:**
        ```
        parquet_data/
        ├── mysql_cve.parquet                    # Main CVE data
        ├── mysql_exploit.parquet                # Exploit information
        ├── mysql_msrc_vuln_unified.parquet     # Microsoft patches
        ├── mysql_cisco_vuln_unified.parquet    # Cisco advisories
        ├── mysql_redhat_vuln_unified.parquet   # RedHat patches
        ├── mysql_github_advisory_unified.parquet # GitHub advisories
        ├── mysql_cwe.parquet                    # CWE reference data
        └── mysql_capec.parquet                  # CAPEC reference data
        ```

=== "Option 2: DuckDB Database File"

    !!! info "Using Pre-built Database"
        A consolidated database file for simplified setup and faster analysis startup.
        
        **Advantages:**
        - Single file download
        - Faster setup process
        - Pre-optimized queries
        - Smaller storage footprint
        
        **Database File:**
        ```
        cve_research.duckdb    # Complete database (~2-3GB)
        ```

## 🛠️ Environment Setup

### Step 1: Create Python Environment

!!! code "Virtual Environment Setup"
    ```bash
    # Create virtual environment
    python -m venv vendor-cwe-analysis
    
    # Activate environment
    # Linux/Mac:
    source vendor-cwe-analysis/bin/activate
    
    # Windows:
    vendor-cwe-analysis\Scripts\activate
    ```

### Step 2: Install Dependencies

!!! code "Package Installation"
    ```bash
    # Core analytics packages
    pip install duckdb>=0.9.0
    pip install pandas>=1.5.0
    pip install numpy>=1.24.0
    
    # Visualization packages
    pip install matplotlib>=3.6.0
    pip install seaborn>=0.12.0
    pip install plotly>=5.15.0
    
    # Jupyter environment
    pip install jupyterlab>=4.0.0
    pip install notebook>=7.0.0
    pip install ipywidgets>=8.0.0
    
    # Statistical analysis
    pip install scipy>=1.11.0
    pip install scikit-learn>=1.3.0
    
    # Optional: Performance enhancement
    pip install modin[all]  # For faster pandas operations
    ```

### Step 3: Verify Installation

!!! code "Installation Verification"
    ```python
    # Test imports
    import duckdb
    import pandas as pd
    import matplotlib.pyplot as plt
    import seaborn as sns
    
    print(f"DuckDB version: {duckdb.__version__}")
    print(f"Pandas version: {pd.__version__}")
    print("✅ All packages installed successfully!")
    ```

## 📊 Data Acquisition

### Option 1: Download Parquet Files

!!! code "Parquet Files Download"
    ```bash
    # Create data directory
    mkdir -p parquet_data
    cd parquet_data
    
    # Download individual parquet files
    # (Replace URLs with actual data source locations)
    
    wget -O mysql_cve.parquet [CVE_DATA_URL]
    wget -O mysql_exploit.parquet [EXPLOIT_DATA_URL]
    wget -O mysql_msrc_vuln_unified.parquet [MSRC_DATA_URL]
    wget -O mysql_cisco_vuln_unified.parquet [CISCO_DATA_URL]
    wget -O mysql_redhat_vuln_unified.parquet [REDHAT_DATA_URL]
    wget -O mysql_github_advisory_unified.parquet [GITHUB_DATA_URL]
    wget -O mysql_cwe.parquet [CWE_REF_URL]
    wget -O mysql_capec.parquet [CAPEC_REF_URL]
    
    # Verify downloads
    ls -la *.parquet
    ```

### Option 2: Download DuckDB Database

!!! code "Database File Download"
    ```bash
    # Download pre-built database
    wget -O cve_research.duckdb [DATABASE_URL]
    
    # Verify download
    ls -la cve_research.duckdb
    ```

### Data Verification

!!! code "Data Quality Check"
    ```python
    import duckdb
    import os
    
    # For parquet files
    if os.path.exists('parquet_data/mysql_cve.parquet'):
        con = duckdb.connect(':memory:')
        con.sql("CREATE VIEW cve_test AS SELECT * FROM 'parquet_data/mysql_cve.parquet'")
        count = con.sql("SELECT COUNT(*) FROM cve_test").fetchone()[0]
        print(f"CVE records loaded: {count:,}")
    
    # For database file
    if os.path.exists('cve_research.duckdb'):
        con = duckdb.connect('cve_research.duckdb')
        tables = con.sql("SHOW TABLES").fetchall()
        print(f"Database tables: {[t[0] for t in tables]}")
    ```

## 🔬 Analysis Execution

### Step 1: Launch Jupyter Environment

!!! code "Jupyter Setup"
    ```bash
    # Launch Jupyter Lab (recommended)
    jupyter lab
    
    # Or launch Jupyter Notebook
    jupyter notebook
    
    # Navigate to the analysis notebook:
    # vendor-cwe-analysis.ipynb
    ```

### Step 2: Configure Data Source

!!! code "Data Configuration"
    ```python
    # In the notebook, set your data source
    USE_PARQUET_FILES = True  # Set to False for DuckDB database
    DATABASE_PATH = 'cve_research.duckdb'
    PARQUET_BASE_PATH = 'parquet_data'
    
    # The notebook will automatically detect and load your data
    ```

### Step 3: Execute Analysis

!!! play "Run Analysis Sections"
    **Section Order:**
    
    1. **Environment Setup** - Import libraries and configure settings
    2. **Data Loading** - Connect to your chosen data source
    3. **Data Quality Assessment** - Verify data integrity
    4. **Vendor CWE Analysis** - Core analysis functions
    5. **Statistical Analysis** - Correlation and pattern analysis
    6. **Visualization Generation** - Create publication-quality figures
    7. **Results Export** - Save results and figures

### Step 4: Monitor Progress

!!! info "Expected Processing Times"
    - **Data Loading**: 2-5 minutes
    - **CWE Analysis**: 10-15 minutes
    - **Statistical Analysis**: 5-10 minutes
    - **Visualization Generation**: 15-20 minutes
    - **Total Runtime**: 30-50 minutes (depending on system)

## 📈 Expected Outputs

### Generated Visualizations

!!! success "Figure Outputs"
    The analysis will generate five publication-quality figures:
    
    ```
    figures/
    ├── Figure1_Vendor_CWE_Comprehensive_Analysis.png
    ├── Figure2_CWE_Vendor_Heatmap.png
    ├── Figure3_CWE_Category_Distribution.png
    ├── Figure4_Vendor_Specialization_Radar.png
    ├── Figure5_Statistical_Analysis.png
    └── statistical_concepts_explanation.png
    ```
    
    **Format**: Both PNG (presentation) and EPS (publication) formats

### Data Exports

!!! success "CSV Outputs"
    ```
    results/
    ├── vendor_cwe_summary.csv           # Summary statistics
    ├── microsoft_cwe_analysis.csv       # Microsoft detailed results
    ├── cisco_cwe_analysis.csv          # Cisco detailed results
    ├── redhat_commercial_analysis.csv   # RedHat Commercial results
    ├── redhat_opensource_analysis.csv   # RedHat Open-Source results
    ├── github_cwe_analysis.csv         # GitHub detailed results
    └── statistical_correlations.json    # Correlation coefficients
    ```

### Console Output Summary

!!! example "Expected Terminal Output"
    ```
    === VENDOR-SPECIFIC CWE ANALYSIS COMPLETE ===
    
    Dataset Overview:
    • Total unique CWEs analyzed: 733
    • Number of vendors/platforms: 5
    • Total CVEs across all vendors: 50,270
    
    Coverage Statistics:
    • Mean CWE coverage: 42.9% (SD: 12.7%)
    • Highest coverage: 60.6% (GitHub Open-Source)
    • Lowest coverage: 27.7% (RedHat Commercial)
    
    Specialization Statistics:
    • Mean specialization: 12.4% (SD: 4.0%)
    • Most specialized: 16.8% (Cisco)
    • Least specialized: 7.2% (RedHat Commercial)
    
    Correlation Analysis:
    • Coverage vs Specialization: r = 0.444
    • Volume vs Diversity: r = 0.958
    ```

## 🔍 Validation Steps

### Data Integrity Checks

!!! check "Verification Checklist"
    
    **✅ Data Loading Verification**
    ```python
    # Check total CVE count
    total_cves = con.sql("SELECT COUNT(*) FROM cve_main").fetchone()[0]
    assert total_cves > 50000, f"Expected >50k CVEs, got {total_cves}"
    
    # Check CWE diversity
    unique_cwes = con.sql("""
        SELECT COUNT(DISTINCT TRIM(UNNEST(STRING_SPLIT(cwe_ids, ','))))
        FROM cve_main WHERE cwe_ids IS NOT NULL
    """).fetchone()[0]
    assert unique_cwes > 700, f"Expected >700 CWEs, got {unique_cwes}"
    ```
    
    **✅ Vendor Data Verification**
    ```python
    # Verify vendor record counts
    vendor_counts = {
        'Microsoft': con.sql("SELECT COUNT(*) FROM msrc_patches").fetchone()[0],
        'Cisco': con.sql("SELECT COUNT(*) FROM cisco_patches").fetchone()[0],
        'RedHat': con.sql("SELECT COUNT(*) FROM redhat_patches").fetchone()[0],
        'GitHub': con.sql("SELECT COUNT(*) FROM github_advisories").fetchone()[0]
    }
    
    for vendor, count in vendor_counts.items():
        print(f"{vendor}: {count:,} records")
        assert count > 0, f"No data found for {vendor}"
    ```

### Statistical Validation

!!! check "Result Validation"
    ```python
    # Validate key statistical findings
    correlations = analysis_results['correlations']
    
    # Coverage vs Specialization correlation
    assert 0.4 < correlations['coverage_specialization'] < 0.5, \
        "Coverage-Specialization correlation outside expected range"
    
    # Volume vs Diversity correlation  
    assert correlations['volume_diversity'] > 0.9, \
        "Volume-Diversity correlation lower than expected"
    
    print("✅ All statistical validations passed")
    ```

### Visual Output Validation

!!! check "Figure Verification"
    ```python
    import os
    
    expected_figures = [
        'Figure1_Vendor_CWE_Comprehensive_Analysis.png',
        'Figure2_CWE_Vendor_Heatmap.png',
        'Figure3_CWE_Category_Distribution.png',
        'Figure4_Vendor_Specialization_Radar.png',
        'Figure5_Statistical_Analysis.png'
    ]
    
    for figure in expected_figures:
        filepath = f'figures/{figure}'
        assert os.path.exists(filepath), f"Missing figure: {figure}"
        
        # Check file size (should be substantial for high-quality figures)
        size_mb = os.path.getsize(filepath) / (1024*1024)
        assert size_mb > 0.1, f"Figure {figure} too small: {size_mb:.2f}MB"
    
    print("✅ All figures generated successfully")
    ```

## 🐛 Troubleshooting

### Common Issues and Solutions

!!! warning "Memory Issues"
    **Problem**: Out of memory errors during analysis
    
    **Solutions:**
    ```python
    # Reduce memory usage
    import gc
    
    # Clear intermediate results
    gc.collect()
    
    # Use chunked processing for large datasets
    chunk_size = 10000
    ```

!!! warning "Data Loading Errors"
    **Problem**: Cannot load parquet files or database
    
    **Solutions:**
    ```bash
    # Check file permissions
    ls -la parquet_data/
    
    # Verify file integrity
    python -c "import pandas as pd; print(pd.read_parquet('parquet_data/mysql_cve.parquet').shape)"
    
    # Re-download corrupted files
    ```

!!! warning "Package Import Errors"
    **Problem**: Module not found errors
    
    **Solutions:**
    ```bash
    # Verify virtual environment activation
    which python
    
    # Reinstall missing packages
    pip install --upgrade duckdb pandas matplotlib seaborn
    
    # Clear pip cache if needed
    pip cache purge
    ```

### Performance Optimization

!!! tip "Speed Improvements"
    **For Large Datasets:**
    ```python
    # Use DuckDB database file (faster than parquet loading)
    USE_PARQUET_FILES = False
    
    # Enable parallel processing
    import os
    os.environ['DUCKDB_THREADS'] = '4'  # Adjust based on CPU cores
    
    # Use memory-mapped files
    con = duckdb.connect(':memory:', config={'memory_limit': '8GB'})
    ```

### Getting Help

!!! question "Support Resources"
    
    **Technical Issues:**
    - Check the [GitHub Issues](https://github.com/your-repo/issues) for similar problems
    - Review DuckDB documentation for SQL query issues
    - Consult pandas documentation for data processing questions
    
    **Research Questions:**
    - Contact: Eid.Albedah@city.ac.uk
    - Include system information and error logs
    - Specify which data source option you're using
    
    **Community Support:**
    - Stack Overflow for technical programming questions
    - Reddit r/MachineLearning for methodology discussions
    - Academic conferences for research collaboration

## 🎯 Customization Options

### Modifying the Analysis

!!! gear "Customization Possibilities"
    
    **Add New Vendors:**
    ```python
    # Add custom vendor analysis
    def analyze_custom_vendor(con, vendor_table, cve_mapping):
        # Implement vendor-specific analysis logic
        pass
    ```
    
    **Adjust Time Periods:**
    ```python
    # Filter by date range
    date_filter = "WHERE date_published >= '2020-01-01' AND date_published <= '2024-12-31'"
    ```
    
    **Custom CWE Categories:**
    ```python
    # Define custom CWE groupings
    custom_categories = {
        'Web Security': ['CWE-79', 'CWE-89', 'CWE-352'],
        'Memory Safety': ['CWE-119', 'CWE-416', 'CWE-787'],
        # Add more categories...
    }
    ```

### Extending the Visualizations

!!! art "Custom Visualizations"
    ```python
    # Add custom plots
    def create_custom_analysis_plot(data):
        fig, ax = plt.subplots(figsize=(12, 8))
        # Custom visualization logic
        plt.savefig('figures/Custom_Analysis.png', dpi=300, bbox_inches='tight')
    ```

---

## 📋 Reproduction Checklist

!!! success "Final Checklist"
    Before considering reproduction complete, verify:
    
    - [ ] **Environment**: Python 3.8+ with all required packages
    - [ ] **Data**: Either parquet files or DuckDB database loaded successfully  
    - [ ] **Analysis**: All notebook cells executed without errors
    - [ ] **Outputs**: Five publication-quality figures generated
    - [ ] **Results**: CSV exports created with expected data
    - [ ] **Validation**: Statistical results match expected ranges
    - [ ] **Documentation**: Analysis log and results documented
    
    **Estimated Total Time**: 2-4 hours
    **Expected Output Size**: ~100MB (figures + results)

---

*For questions or issues with reproduction, contact: Eid.Albedah@city.ac.uk*

*Last updated: {{ now().strftime('%B %Y') }}*