# Chapter 4: CVE Analysis (Enhanced Multi-Vendor)

## Overview

This chapter presents an enhanced reproduction of the CVE analysis from the transfer report, now expanded with multi-vendor data sources and updated through May 2025. The analysis maintains the original structure while adding comparative insights across commercial and open source ecosystems.

This document provides SQL queries (DuckDB syntax) and Apache Superset configuration details for visualizing your updated vulnerability, exploit, and patching data up to May 13, 2025.

## **Data Preparation Notes:**

* **Date Filtering**: All queries implicitly filter date_published or release_date up to '2025-05-13'. You can adjust this date in Superset's time filter or directly in the SQL.  
* **Unnesting/Splitting**: For columns like cpes, vendors, and cwe_ids which are comma-separated strings, STRING_SPLIT_BY_REGEX is used to convert them into arrays, followed by UNNEST to expand them into separate rows for aggregation.  
* **Patch Data Unification**: For analyses requiring comprehensive patch data across vendors, a UNION ALL approach is used to combine msrc_patches, redhat_patches, cisco_patches, github_advisories, and morefixes_fixes.  
  * **Red Hat Filtering**: Remember to apply the specified Red Hat product filtering (product_name or product_id containing rh, red hat, red-hat, rhel, enterprise linux, baseos, appstream, openshift) for official Red Hat products. This is included in the Red Hat specific queries.  
  * **GitHub Advisories**: github_advisories is included where patched = 1 or patch_available = 1.  
  * **MoreFixes**: morefixes_fixes is joined with morefixes_commits to get the author_date as the patch date.  
* **Severity Mapping**: CVSS v3 severity is used where available.

<div class="superset-embed">
    <iframe
        width="100%"
        height="100%"
        seamless
        frameBorder="0"
        scrolling="yes"
        src="https://analytic.ifthreat.com/superset/dashboard/chapter-4/?standalone=1&height=1080&show_filters=1"
        loading="lazy">
    </iframe>
    <p class="chart-caption">📊 Chapter 4: Complete CVE Analysis Dashboard - Interactive Multi-Vendor Analysis</p>
</div>

## **CVE Analysis**

### **Ch4_Fig_4.1_Annual distribution of CVEs from 1999 to 2025**

* **Question Answered**: How has the number of reported CVEs changed over the years?  
* **SQL Query**:  
```sql
SELECT 
    STRFTIME(date_published, '%Y') AS year,
    COUNT(cve_id) AS cve_count
FROM 
    cve_main 
WHERE 
    state = 'PUBLISHED'
    AND date_published <= '2025-05-13'
    AND date_published >= '1999-01-01'
GROUP BY 
    year
ORDER BY 
    year;
```

* **Superset Chart Type**: Line Chart  
* **Superset Configuration**:  
  * **Time Column**: date_published (set to YEAR grain)  
  * **Metrics**: COUNT(cve_id)  
  * **Group By**: year (from SQL output)  
  * **Time Range**: Custom, e.g., 1999-01-01 to 2025-05-13

### **Ch4_Tab_4.1_Distribution of CVEs by severity level**

* **Question Answered**: What is the breakdown of CVEs by their CVSS severity rating (Low, Medium, High, Critical)?  
* **SQL Query**:  
```sql
WITH CombinedCVEData AS (
    SELECT
        'CVSS v2' AS cvss_version,
        CASE
            WHEN cvss_v2_score >= 7.0 THEN 'HIGH'
            WHEN cvss_v2_score >= 4.0 THEN 'MEDIUM'
            WHEN cvss_v2_score > 0.0 THEN 'LOW'
            ELSE 'UNKNOWN'
        END AS severity_level,
        COUNT(cve_id) AS cve_count,
        ROUND(COUNT(cve_id) * 100.0 / SUM(COUNT(cve_id)) OVER (PARTITION BY 'CVSS v2'), 2) AS percentage
    FROM
        cve_main
    WHERE
        state = 'PUBLISHED'
        AND cvss_v2_score IS NOT NULL
        AND cvss_v2_score != -1
        AND date_published <= '2025-05-13'
    GROUP BY
        cvss_version, severity_level

    UNION ALL

    SELECT
        'CVSS v3' AS cvss_version,
        cvss_v3_severity AS severity_level,
        COUNT(cve_id) AS cve_count,
        ROUND(COUNT(cve_id) * 100.0 / SUM(COUNT(cve_id)) OVER (PARTITION BY 'CVSS v3'), 2) AS percentage
    FROM
        cve_main
    WHERE
        state = 'PUBLISHED'
        AND cvss_v3_severity IS NOT NULL
        AND cvss_v3_severity != ''
        AND date_published <= '2025-05-13'
    GROUP BY
        cvss_version, severity_level

    UNION ALL

    SELECT
        'CVSS v4' AS cvss_version,
        cvss_v4_severity AS severity_level,
        COUNT(cve_id) AS cve_count,
        ROUND(COUNT(cve_id) * 100.0 / SUM(COUNT(cve_id)) OVER (PARTITION BY 'CVSS v4'), 2) AS percentage
    FROM
        cve_main
    WHERE
        state = 'PUBLISHED'
        AND cvss_v4_severity IS NOT NULL
        AND cvss_v4_severity != ''
        AND date_published <= '2025-05-13'
    GROUP BY
        cvss_version, severity_level
)
SELECT
    cvss_version,
    severity_level,
    cve_count,
    percentage
FROM
    CombinedCVEData
ORDER BY
    cvss_version,
    CASE severity_level
        WHEN 'CRITICAL' THEN 1
        WHEN 'HIGH' THEN 2
        WHEN 'MEDIUM' THEN 3
        WHEN 'LOW' THEN 4
        ELSE 5
    END;
```

* **Superset Chart Type**: Table or Pie Chart / Donut Chart  
* **Superset Configuration**:  
  * **Table**:  
    * **Columns**: severity_level, cve_count  
  * **Pie/Donut Chart**:  
    * **Group By**: severity_level  
    * **Metrics**: COUNT(cve_id)

* **Superset Configuration**:

- Columns: cvss_version, severity_level, cve_count, percentage
- Sort By: cvss_version, then severity_level (Critical → High → Medium → Low)
- Chart Title: "Distribution of CVEs by severity level"
- Table Options: Format percentage column to show % symbol

### **Ch4_Fig_4.2_Annual distribution of CVE CVSS scores (1999-2025)**

* **Question Answered**: How has the severity of reported CVEs evolved over time across different CVSS versions?  
* **SQL Query**:  
```sql
SELECT 
    STRFTIME(date_published, '%Y') AS year,
    'CVSS v2' AS cvss_version,
    AVG(cvss_v2_score) AS average_cvss_score,
    COUNT(cve_id) AS cve_count
FROM 
    cve_main 
WHERE 
    state = 'PUBLISHED'
    AND cvss_v2_score IS NOT NULL 
    AND cvss_v2_score != -1
    AND date_published <= '2025-05-13'
    AND date_published >= '1999-01-01'
GROUP BY 
    year, cvss_version

UNION ALL

SELECT 
    STRFTIME(date_published, '%Y') AS year,
    'CVSS v3' AS cvss_version,
    AVG(cvss_v3_score) AS average_cvss_score,
    COUNT(cve_id) AS cve_count
FROM 
    cve_main 
WHERE 
    state = 'PUBLISHED'
    AND cvss_v3_score IS NOT NULL 
    AND cvss_v3_score != -1
    AND date_published <= '2025-05-13'
    AND date_published >= '1999-01-01'
GROUP BY 
    year, cvss_version

UNION ALL

SELECT 
    STRFTIME(date_published, '%Y') AS year,
    'CVSS v4' AS cvss_version,
    AVG(cvss_v4_score) AS average_cvss_score,
    COUNT(cve_id) AS cve_count
FROM 
    cve_main 
WHERE 
    state = 'PUBLISHED'
    AND cvss_v4_score IS NOT NULL 
    AND cvss_v4_score != -1
    AND date_published <= '2025-05-13'
    AND date_published >= '1999-01-01'
GROUP BY 
    year, cvss_version
ORDER BY 
    year, cvss_version;
```
* **Superset Chart Type**: Line Chart  
* **Superset Configuration**:  
  * **Time Column**: date_published (set to YEAR grain)  
  * **Metrics**: AVG(cvss_v3_score)  
  * **Group By**: year (from SQL output)  
  * **Time Range**: Custom, e.g., 1999-01-01 to 2025-05-13

* **Superset Chart Type**: Line Chart
* **Superset Configuration**:

  * **X-axis**: year
  * **Y-axis**: average_cvss_score
  * **Group By**: cvss_version
  * **Time Range**: Custom, 1999-01-01 to 2025-05-13
  * **Chart Title**: "Annual distribution of CVE CVSS scores (1999-2025)"
  * **Y-axis**: Set range from 0 to 10 for CVSS scores
  * **Legend**: Show different lines for each CVSS version

### **Ch4_Fig_4.3_Top 10 Vulnerable Products**

* **Question Answered**: Which software products have the highest number of associated vulnerabilities?  
* **SQL Query**:  
```sql
WITH cpe_split AS (
    SELECT 
        cve_id,
        TRIM(UNNEST(STRING_SPLIT(cpes, ','))) as cpe_entry
    FROM cve_main 
    WHERE cpes IS NOT NULL 
        AND cpes != ''
        AND state = 'PUBLISHED'
        AND date_published <= '2025-05-13'
),
product_cve_mapping AS (
    SELECT 
        cve_id,
        SPLIT_PART(cpe_entry, ':', 5) as product,
        SPLIT_PART(cpe_entry, ':', 4) as vendor
    FROM cpe_split
    WHERE cpe_entry LIKE 'cpe:%'
),
product_clean AS (
    SELECT 
        cve_id,
        LOWER(TRIM(product)) as product,
        LOWER(TRIM(vendor)) as vendor
    FROM product_cve_mapping
    WHERE product IS NOT NULL 
        AND product != ''
        AND product != '*'
        AND vendor IS NOT NULL
        AND vendor != ''
        AND vendor != '*'
        AND LENGTH(product) > 2
        AND LENGTH(vendor) > 1
)
SELECT 
    product,
    vendor,
    COUNT(DISTINCT cve_id) as unique_cves,
    COUNT(cve_id) as total_instances
FROM product_clean
GROUP BY product, vendor
HAVING COUNT(DISTINCT cve_id) >= 100
ORDER BY unique_cves DESC
LIMIT 10;
```

* **Superset Chart Type**: Bar Chart (Horizontal)  
* **Superset Configuration**:  
  * **X-axis**: cve_count  
  * **Y-axis**: product_name  
  * **Sort By**: cve_count (Descending)  
  * **Limit**: 10

### **Ch4_Fig_4.4_Top 10 Vulnerable Vendors**

* **Question Answered**: Which vendors have the highest number of vulnerabilities across their products?  
* **SQL Query**:  
 ```sql
 WITH cpe_split AS (
    SELECT 
        cve_id,
        TRIM(UNNEST(STRING_SPLIT(cpes, ','))) as cpe_entry
    FROM cve_main 
    WHERE cpes IS NOT NULL 
        AND cpes != ''
        AND state = 'PUBLISHED'
        AND date_published <= '2025-05-13'
),
vendor_cve_mapping AS (
    SELECT 
        cve_id,
        SPLIT_PART(cpe_entry, ':', 4) as vendor
    FROM cpe_split
    WHERE cpe_entry LIKE 'cpe:%'
),
vendor_clean AS (
    SELECT 
        cve_id,
        LOWER(TRIM(vendor)) as vendor
    FROM vendor_cve_mapping
    WHERE vendor IS NOT NULL 
        AND vendor != ''
        AND vendor != '*'
        AND LENGTH(vendor) > 1
)
SELECT 
    vendor,
    COUNT(DISTINCT cve_id) as unique_cves,
    COUNT(cve_id) as total_instances
FROM vendor_clean
GROUP BY vendor
HAVING COUNT(DISTINCT cve_id) >= 200
ORDER BY unique_cves DESC
LIMIT 10;
 ```

* **Superset Chart Type**: Bar Chart (Horizontal)  
* **Superset Configuration**:  
  * **X-axis**: cve_count  
  * **Y-axis**: vendor_name  
  * **Sort By**: cve_count (Descending)  
  * **Limit**: 10

### **Ch4_Fig_4.5_Distribution of CVEs with or without associated CWE**

* **Question Answered**: What is the trend of associating CVEs with specific Common Weakness Enumerations (CWEs) over time?  
* **SQL Query**:  
```sql
SELECT 
    STRFTIME(date_published, '%Y') AS year,
    CASE 
        WHEN cwe_ids IS NOT NULL AND cwe_ids != '' AND cwe_ids NOT LIKE '%NVD-CWE%' THEN 'With CWE'
        ELSE 'Without CWE'
    END AS cwe_status,
    COUNT(cve_id) AS cve_count
FROM 
    cve_main 
WHERE 
    state = 'PUBLISHED'
    AND date_published <= '2025-05-13'
    AND date_published >= '1999-01-01'
GROUP BY 
    year, cwe_status
ORDER BY 
    year, cwe_status;
```

* **Superset Chart Type**: Stacked Bar Chart or Line Chart  
* **Superset Configuration**:  
  * **X-axis**: year  
  * **Y-axis**: cve_count  
  * **Stack By / Group By**: cwe_status  
  * **Time Range**: Custom, e.g., 1999-01-01 to 2025-05-13

### **Ch4_Tab_4.2_Top 10 CWEs associated with CVEs**

* **Question Answered**: What are the most common types of weaknesses (CWEs) found in reported vulnerabilities?  
* **SQL Query**:  
```sql
WITH cwe_split AS (
    SELECT 
        cve_id,
        TRIM(UNNEST(STRING_SPLIT(cwe_ids, ','))) as cwe_id
    FROM cve_main 
    WHERE cwe_ids IS NOT NULL 
        AND cwe_ids != ''
        AND state = 'PUBLISHED'
        AND date_published <= '2025-05-13'
),
cwe_counts AS (
    SELECT 
        cs.cwe_id,
        COUNT(DISTINCT cs.cve_id) AS cve_count
    FROM cwe_split cs
    WHERE cs.cwe_id IS NOT NULL 
        AND cs.cwe_id != ''
        AND cs.cwe_id LIKE 'CWE-%'
    GROUP BY cs.cwe_id
)
SELECT 
    cc.cwe_id,
    cr.name AS cwe_name,
    cc.cve_count,
    ROUND(cc.cve_count * 100.0 / SUM(cc.cve_count) OVER (), 2) AS percentage
FROM cwe_counts cc
LEFT JOIN cwe_ref cr ON cc.cwe_id = cr.cwe_id
ORDER BY cc.cve_count DESC
LIMIT 10;
```

* **Superset Chart Type**: Table or Bar Chart (Horizontal)  
* **Superset Configuration**:  
  * **Table**:  
    * **Columns**: cwe_id, cwe_name, cve_count  
  * **Bar Chart**:  
    * **X-axis**: cve_count  
    * **Y-axis**: cwe_name  
    * **Sort By**: cve_count (Descending)  
    * **Limit**: 10

### **Ch4_Tab_4.3_Top 10 Common Weakness Enumerations by Occurrence**

* **Question Answered**: What are the long-term trends and key insights for the most frequently occurring CWEs?  
* **SQL Query**: (This query provides the total counts. For "Trend" and "Key Insight", these would typically be added manually or require more complex pre-processing outside Superset, or separate charts for trends.)  
```sql
WITH cwe_split AS (
    SELECT 
        cve_id,
        TRIM(UNNEST(STRING_SPLIT(cwe_ids, ','))) as cwe_id
    FROM cve_main 
    WHERE cwe_ids IS NOT NULL 
        AND cwe_ids != ''
        AND state = 'PUBLISHED'
        AND date_published <= '2025-05-13'
),
cwe_counts AS (
    SELECT 
        cs.cwe_id,
        COUNT(DISTINCT cs.cve_id) AS total_cves
    FROM cwe_split cs
    WHERE cs.cwe_id IS NOT NULL 
        AND cs.cwe_id != ''
        AND cs.cwe_id LIKE 'CWE-%'
    GROUP BY cs.cwe_id
)
SELECT 
    cc.cwe_id,
    cr.name AS cwe_name,
    cc.total_cves,
    cr.weakness_abstraction,
    cr.status,
    ROUND(cc.total_cves * 100.0 / SUM(cc.total_cves) OVER (), 2) AS percentage
FROM cwe_counts cc
LEFT JOIN cwe_ref cr ON cc.cwe_id = cr.cwe_id
ORDER BY cc.total_cves DESC
LIMIT 10;
```

* **Superset Chart Type**: Table  
* **Superset Configuration**:  
  * **Columns**: cwe_id, cwe_name, total_cves

### **Ch4_Fig_4.6_Temporal Distribution of Top 10 Recurring CWEs**

* **Question Answered**: How has the occurrence of the top 10 CWEs changed year over year?  
* **SQL Query**:  
```sql
WITH cwe_split AS (
    SELECT 
        cve_id,
        date_published,
        TRIM(UNNEST(STRING_SPLIT(cwe_ids, ','))) as cwe_id
    FROM cve_main 
    WHERE cwe_ids IS NOT NULL 
        AND cwe_ids != ''
        AND state = 'PUBLISHED'
        AND date_published <= '2025-05-13'
        AND date_published >= '1999-01-01'
),
top_cwes AS (
    SELECT 
        cwe_id
    FROM cwe_split
    WHERE cwe_id LIKE 'CWE-%'
    GROUP BY cwe_id
    ORDER BY COUNT(DISTINCT cve_id) DESC
    LIMIT 10
),
yearly_cwe_counts AS (
    SELECT 
        STRFTIME(cs.date_published, '%Y') AS year,
        cs.cwe_id,
        COUNT(DISTINCT cs.cve_id) AS cve_count
    FROM cwe_split cs
    WHERE cs.cwe_id IN (SELECT cwe_id FROM top_cwes)
    GROUP BY year, cs.cwe_id
)
SELECT 
    ycc.year,
    ycc.cwe_id,
    cr.name AS cwe_name,
    ycc.cve_count
FROM yearly_cwe_counts ycc
LEFT JOIN cwe_ref cr ON ycc.cwe_id = cr.cwe_id
ORDER BY ycc.year, ycc.cve_count DESC;
```

* **Superset Chart Type**: Line Chart  
* **Superset Configuration**:  
  * **X-axis**: year  
  * **Y-axis**: cve_count  
  * **Group By**: cwe_name  
  * **Time Range**: Custom, e.g., 1999-01-01 to 2025-05-13

### **Ch4_Tab_4.4_Summary of Top 10 Most Recurring CWEs Over the Years**

* **Question Answered**: Which years were most significant for the top 10 recurring CWEs in terms of CVE counts?  
* **SQL Query**: (This query identifies the year with the max CVEs for each of the top 10 CWEs. Superset can display this as a table.)  
```sql
WITH cwe_split AS (
    SELECT 
        cve_id,
        date_published,
        TRIM(UNNEST(STRING_SPLIT(cwe_ids, ','))) as cwe_id
    FROM cve_main 
    WHERE cwe_ids IS NOT NULL 
        AND cwe_ids != ''
        AND state = 'PUBLISHED'
        AND date_published <= '2025-05-13'
        AND date_published >= '1999-01-01'
),
yearly_cwe_counts AS (
    SELECT 
        STRFTIME(cs.date_published, '%Y') AS year,
        cs.cwe_id,
        COUNT(DISTINCT cs.cve_id) AS annual_cve_count
    FROM cwe_split cs
    WHERE cs.cwe_id LIKE 'CWE-%'
    GROUP BY year, cs.cwe_id
),
top_cwes_with_peak AS (
    SELECT 
        ycc.cwe_id,
        SUM(ycc.annual_cve_count) AS total_cves,
        MAX_BY(ycc.year, ycc.annual_cve_count) AS peak_year,
        MAX(ycc.annual_cve_count) AS peak_year_count
    FROM yearly_cwe_counts ycc
    GROUP BY ycc.cwe_id
    ORDER BY total_cves DESC
    LIMIT 10
)
SELECT 
    tc.cwe_id,
    cr.name AS cwe_name,
    tc.total_cves,
    tc.peak_year,
    tc.peak_year_count,
    ROUND(tc.peak_year_count * 100.0 / tc.total_cves, 2) AS peak_year_percentage
FROM top_cwes_with_peak tc
LEFT JOIN cwe_ref cr ON tc.cwe_id = cr.cwe_id
ORDER BY tc.total_cves DESC;
```

* **Superset Chart Type**: Table  
* **Superset Configuration**:  
  * **Columns**: cwe_id, cwe_name, total_cves, year_with_max_cves

### **Ch4_Fig_4.7_Distribution of the Top 10 Reoccurring CWEs Over Time for the period (2019–2025)**

* **Question Answered**: What have been the most common CWEs in the last five years?  
* **SQL Query**:  
```sql
WITH cwe_split AS (
    SELECT 
        cve_id,
        date_published,
        TRIM(UNNEST(STRING_SPLIT(cwe_ids, ','))) as cwe_id
    FROM cve_main 
    WHERE cwe_ids IS NOT NULL 
        AND cwe_ids != ''
        AND state = 'PUBLISHED'
        AND date_published <= '2025-05-13'
        AND STRFTIME(date_published, '%Y') BETWEEN '2019' AND '2025'
),
top_cwes_2019_2025 AS (
    SELECT 
        cwe_id
    FROM cwe_split
    WHERE cwe_id LIKE 'CWE-%'
    GROUP BY cwe_id
    ORDER BY COUNT(DISTINCT cve_id) DESC
    LIMIT 10
),
yearly_cwe_counts AS (
    SELECT 
        STRFTIME(cs.date_published, '%Y') AS year,
        cs.cwe_id,
        COUNT(DISTINCT cs.cve_id) AS cve_count
    FROM cwe_split cs
    WHERE cs.cwe_id IN (SELECT cwe_id FROM top_cwes_2019_2025)
    GROUP BY year, cs.cwe_id
)
SELECT 
    ycc.year,
    ycc.cwe_id,
    cr.name AS cwe_name,
    ycc.cve_count
FROM yearly_cwe_counts ycc
LEFT JOIN cwe_ref cr ON ycc.cwe_id = cr.cwe_id
ORDER BY ycc.year, ycc.cve_count DESC;
```

* **Superset Chart Type**: Line Chart  
* **Superset Configuration**:  
  * **X-axis**: year  
  * **Y-axis**: cve_count  
  * **Group By**: cwe_name  
  * **Time Range**: Custom, 2019-01-01 to 2023-12-31 (or 2025-05-13 if you want to extend beyond 2023 for the current data)

### **Ch4_Tab_4.5_Top 10 CWEs (2019–2025)**

* **Question Answered**: What are the most frequent CWEs in recent years (2019-2023) by count and percentage?  
* **SQL Query**:  
```sql
WITH cwe_split AS (
    SELECT 
        cve_id,
        TRIM(UNNEST(STRING_SPLIT(cwe_ids, ','))) as cwe_id
    FROM cve_main 
    WHERE cwe_ids IS NOT NULL 
        AND cwe_ids != ''
        AND state = 'PUBLISHED'
        AND date_published <= '2025-05-13'
        AND STRFTIME(date_published, '%Y') BETWEEN '2019' AND '2025'
),
cwe_counts_2019_2025 AS (
    SELECT 
        cs.cwe_id,
        COUNT(DISTINCT cs.cve_id) AS cve_count
    FROM cwe_split cs
    WHERE cs.cwe_id LIKE 'CWE-%'
    GROUP BY cs.cwe_id
)
SELECT 
    cc.cwe_id,
    cr.name AS cwe_name,
    cc.cve_count,
    ROUND(cc.cve_count * 100.0 / SUM(cc.cve_count) OVER (), 2) AS percentage
FROM cwe_counts_2019_2025 cc
LEFT JOIN cwe_ref cr ON cc.cwe_id = cr.cwe_id
ORDER BY cc.cve_count DESC
LIMIT 10;
```

* **Superset Chart Type**: Table  
* **Superset Configuration**:  
  * **Columns**: cwe_id, cwe_name, cve_count, percentage

### **Ch4_Fig_4.8_Top 2 CWEs and Related CVE Scores Over Time**

* **Question Answered**: Has the severity of the top 2 most common CWEs changed over time?  
* **SQL Query**: (Assuming CWE-79 and CWE-119 are the top 2 based on your previous analysis)  
```sql
WITH cwe_split AS (
    SELECT 
        cve_id,
        date_published,
        TRIM(UNNEST(STRING_SPLIT(cwe_ids, ','))) as cwe_id
    FROM cve_main 
    WHERE cwe_ids IS NOT NULL 
        AND cwe_ids != ''
        AND state = 'PUBLISHED'
        AND date_published <= '2025-05-13'
        AND date_published >= '1999-01-01'
),
top_2_cwes AS (
    SELECT 
        cwe_id
    FROM cwe_split
    WHERE cwe_id LIKE 'CWE-%'
    GROUP BY cwe_id
    ORDER BY COUNT(DISTINCT cve_id) DESC
    LIMIT 2
),
yearly_cwe_severity AS (
    SELECT 
        STRFTIME(cm.date_published, '%Y') AS year,
        cs.cwe_id,
        AVG(cm.cvss_v3_score) AS avg_cvss_score,
        COUNT(DISTINCT cm.cve_id) AS cve_count
    FROM cve_main cm
    JOIN cwe_split cs ON cm.cve_id = cs.cve_id
    WHERE cs.cwe_id IN (SELECT cwe_id FROM top_2_cwes)
        AND cm.cvss_v3_score IS NOT NULL 
        AND cm.cvss_v3_score != -1
    GROUP BY year, cs.cwe_id
)
SELECT 
    ycs.year,
    ycs.cwe_id,
    cr.name AS cwe_name,
    ROUND(ycs.avg_cvss_score, 2) AS average_cvss_score,
    ycs.cve_count
FROM yearly_cwe_severity ycs
LEFT JOIN cwe_ref cr ON ycs.cwe_id = cr.cwe_id
ORDER BY ycs.year, ycs.cwe_id;
```

* **Superset Chart Type**: Line Chart  
* **Superset Configuration**:  
  * **X-axis**: year  
  * **Y-axis**: average_cvss_score  
  * **Group By**: cwe_name  
  * **Time Range**: Custom, e.g., 1999-01-01 to 2025-05-13

### **Ch4_Tab_4.7_Top 10 weaknesses and their exploitation status**

* **Question Answered**: Which common weaknesses (CWEs) are most frequently exploited?  
* **SQL Query**:  
```sql
WITH cwe_split AS (
    SELECT
        cve_id,
        TRIM(UNNEST(STRING_SPLIT(cwe_ids, ','))) as cwe_id
    FROM cve_main
    WHERE cwe_ids IS NOT NULL
        AND cwe_ids != ''
        AND state = 'PUBLISHED'
        AND date_published <= '2025-05-13'
),
cwe_exploitation_stats AS (
    SELECT
        cs.cwe_id,
        COUNT(DISTINCT cs.cve_id) AS total_cves,
        COUNT(DISTINCT CASE WHEN cm.has_exploit = 1 THEN cs.cve_id END) AS exploited_cves,
        COUNT(DISTINCT CASE WHEN cm.kev_known_exploited = 1 THEN cs.cve_id END) AS kev_exploited_cves,
        -- New: Count exploited CVEs by verified status
        COUNT(DISTINCT CASE WHEN ex.verified = TRUE THEN cs.cve_id END) AS verified_exploited_cves,
        COUNT(DISTINCT CASE WHEN ex.verified = FALSE THEN cs.cve_id END) AS unverified_exploited_cves
    FROM cwe_split cs
    JOIN cve_main cm ON cs.cve_id = cm.cve_id
    LEFT JOIN exploits ex ON cm.cve_id = ex.cve_id -- Join with exploits table
    WHERE cs.cwe_id LIKE 'CWE-%'
    GROUP BY cs.cwe_id
)
SELECT
    ces.cwe_id,
    cr.name AS cwe_name,
    ces.total_cves,
    ces.exploited_cves,
    ces.kev_exploited_cves,
    ces.verified_exploited_cves,   -- New column
    ces.unverified_exploited_cves, -- New column
    ROUND(ces.exploited_cves * 100.0 / ces.total_cves, 2) AS exploitation_rate,
    ROUND(ces.kev_exploited_cves * 100.0 / ces.total_cves, 2) AS kev_exploitation_rate,
    -- Optional: calculate rates for verified/unverified
    CASE WHEN ces.exploited_cves > 0 THEN ROUND(ces.verified_exploited_cves * 100.0 / ces.exploited_cves, 2) ELSE 0 END AS verified_exploitation_rate,
    CASE WHEN ces.exploited_cves > 0 THEN ROUND(ces.unverified_exploited_cves * 100.0 / ces.exploited_cves, 2) ELSE 0 END AS unverified_exploitation_rate
FROM cwe_exploitation_stats ces
LEFT JOIN cwe_ref cr ON ces.cwe_id = cr.cwe_id
WHERE ces.exploited_cves > 0 -- Only show CWEs that have been exploited
ORDER BY ces.exploited_cves DESC
LIMIT 10;
```

* **Superset Chart Type**: Table or Bar Chart (Horizontal)  
* **Superset Configuration**:  
  * **Table**:  
    * **Columns**: cwe_id, cwe_name, exploited_cve_count  
  * **Bar Chart**:  
    * **X-axis**: exploited_cve_count  
    * **Y-axis**: cwe_name  
    * **Sort By**: exploited_cve_count (Descending)  
    * **Limit**: 10

### **Ch4_Fig_4.9_Distribution of CVEs by number of CWEs**

* **Question Answered**: How many CWEs are typically associated with a single CVE?  
* **SQL Query**:  
```sql
WITH cve_cwe_counts AS (
    SELECT 
        cve_id,
        CASE 
            WHEN cwe_ids IS NULL OR cwe_ids = '' OR cwe_ids LIKE '%NVD-CWE%' THEN 0
            ELSE ARRAY_LENGTH(STRING_SPLIT(cwe_ids, ','))
        END AS num_cwes
    FROM cve_main 
    WHERE state = 'PUBLISHED'
        AND date_published <= '2025-05-13'
)
SELECT 
    num_cwes,
    COUNT(cve_id) AS cve_count,
    ROUND(COUNT(cve_id) * 100.0 / SUM(COUNT(cve_id)) OVER (), 2) AS percentage
FROM cve_cwe_counts
GROUP BY num_cwes
ORDER BY num_cwes;
```

* **Superset Chart Type**: Bar Chart  
* **Superset Configuration**:  
  * **X-axis**: num_cwes  
  * **Y-axis**: cve_count

### **Ch4_Fig_4.10_Top 10 most common CWE pairs found in vulnerabilities**

* **Question Answered**: What are the most common combinations of two CWEs co-occurring in a single vulnerability?  
* **SQL Query**: (This query generates pairs. Superset might struggle to visualize this directly as a network graph. A table or a bar chart of the top pairs is more feasible.)  
```sql
WITH cwe_split AS (
    SELECT 
        cve_id,
        TRIM(UNNEST(STRING_SPLIT(cwe_ids, ','))) as cwe_id
    FROM cve_main 
    WHERE cwe_ids IS NOT NULL 
        AND cwe_ids != ''
        AND state = 'PUBLISHED'
        AND date_published <= '2025-05-13'
        AND ARRAY_LENGTH(STRING_SPLIT(cwe_ids, ',')) >= 2  -- Only CVEs with 2+ CWEs
),
cwe_pairs AS (
    SELECT 
        c1.cve_id,
        c1.cwe_id AS cwe1,
        c2.cwe_id AS cwe2
    FROM cwe_split c1
    JOIN cwe_split c2 ON c1.cve_id = c2.cve_id
    WHERE c1.cwe_id < c2.cwe_id  -- Ensures unique pairs (e.g., CWE-1,CWE-2 but not CWE-2,CWE-1)
        AND c1.cwe_id LIKE 'CWE-%'
        AND c2.cwe_id LIKE 'CWE-%'
),
pair_counts AS (
    SELECT 
        cwe1,
        cwe2,
        COUNT(DISTINCT cve_id) AS pair_count
    FROM cwe_pairs
    GROUP BY cwe1, cwe2
)
SELECT 
    pc.cwe1,
    pc.cwe2,
    cr1.name AS cwe1_name,
    cr2.name AS cwe2_name,
    pc.pair_count,
    CONCAT(pc.cwe1, ' & ', pc.cwe2) AS cwe_pair_label
FROM pair_counts pc
LEFT JOIN cwe_ref cr1 ON pc.cwe1 = cr1.cwe_id
LEFT JOIN cwe_ref cr2 ON pc.cwe2 = cr2.cwe_id
ORDER BY pc.pair_count DESC
LIMIT 10;
```

* **Superset Chart Type**: Table or Bar Chart (Horizontal)  
* **Superset Configuration**:  
  * **Table**:  
    * **Columns**: cwe1_name, cwe2_name, pair_count  
  * **Bar Chart**:  
    * **X-axis**: pair_count  
    * **Y-axis**: cwe1_name || ' & ' || cwe2_name (if Superset supports concatenation in Y-axis)  
    * **Sort By**: pair_count (Descending)  
    * **Limit**: 10

### **Ch4_Fig_4.11_Relationship diagram of common CWE pairs showing the top vulnerability clusters**

* **Question Answered**: How can the relationships between common CWE pairs be visualized to show vulnerability clusters?  
* **Superset Chart Type**: Not directly supported as a dynamic graph visualization. This is a conceptual diagram. You would need to use an external tool (e.g., Mermaid, Graphviz, or manually create in a design tool) and embed it as an image in a Superset dashboard.

### **Ch4_Fig_4.12_Top 7 most common CWE triplets found in vulnerabilities**

* **Question Answered**: What are the most common combinations of three CWEs co-occurring in a single vulnerability?  
* **SQL Query**: (Similar to pairs, but for triplets. Best presented as a table in Superset.)  
```sql
WITH cwe_split AS (
    SELECT 
        cve_id,
        TRIM(UNNEST(STRING_SPLIT(cwe_ids, ','))) as cwe_id
    FROM cve_main 
    WHERE cwe_ids IS NOT NULL 
        AND cwe_ids != ''
        AND state = 'PUBLISHED'
        AND date_published <= '2025-05-13'
        AND ARRAY_LENGTH(STRING_SPLIT(cwe_ids, ',')) >= 3  -- Only CVEs with 3+ CWEs
),
cwe_triplets AS (
    SELECT 
        c1.cve_id,
        c1.cwe_id AS cwe1,
        c2.cwe_id AS cwe2,
        c3.cwe_id AS cwe3
    FROM cwe_split c1
    JOIN cwe_split c2 ON c1.cve_id = c2.cve_id
    JOIN cwe_split c3 ON c1.cve_id = c3.cve_id
    WHERE c1.cwe_id < c2.cwe_id 
        AND c2.cwe_id < c3.cwe_id  -- Ensures unique triplets in order
        AND c1.cwe_id LIKE 'CWE-%'
        AND c2.cwe_id LIKE 'CWE-%'
        AND c3.cwe_id LIKE 'CWE-%'
),
triplet_counts AS (
    SELECT 
        cwe1,
        cwe2,
        cwe3,
        COUNT(DISTINCT cve_id) AS triplet_count
    FROM cwe_triplets
    GROUP BY cwe1, cwe2, cwe3
)
SELECT 
    tc.cwe1,
    tc.cwe2,
    tc.cwe3,
    cr1.name AS cwe1_name,
    cr2.name AS cwe2_name,
    cr3.name AS cwe3_name,
    tc.triplet_count,
    CONCAT(tc.cwe1, ' & ', tc.cwe2, ' & ', tc.cwe3) AS cwe_triplet_label
FROM triplet_counts tc
LEFT JOIN cwe_ref cr1 ON tc.cwe1 = cr1.cwe_id
LEFT JOIN cwe_ref cr2 ON tc.cwe2 = cr2.cwe_id
LEFT JOIN cwe_ref cr3 ON tc.cwe3 = cr3.cwe_id
ORDER BY tc.triplet_count DESC
LIMIT 7;
```

* **Superset Chart Type**: Table  
* **Superset Configuration**:  
  * **Columns**: cwe1_name, cwe2_name, cwe3_name, triplet_count

### **Ch4_Tab_4.8_CWE IDs mentioned in pairs, triplets analysis and Their Descriptions**

* **Question Answered**: What are the descriptions for the CWEs discussed in the pair and triplet analysis?  
* **SQL Query**: (You would typically filter this for the specific CWE IDs identified in your pair/triplet analysis results.)  
```sql
WITH cwe_split AS (
    SELECT 
        cve_id,
        TRIM(UNNEST(STRING_SPLIT(cwe_ids, ','))) as cwe_id
    FROM cve_main 
    WHERE cwe_ids IS NOT NULL 
        AND cwe_ids != ''
        AND state = 'PUBLISHED'
        AND date_published <= '2025-05-13'
        AND ARRAY_LENGTH(STRING_SPLIT(cwe_ids, ',')) >= 2  -- CVEs with 2+ CWEs for pairs/triplets
),
frequent_cwes_in_combinations AS (
    SELECT DISTINCT cwe_id
    FROM cwe_split
    WHERE cwe_id LIKE 'CWE-%'
    GROUP BY cwe_id
    HAVING COUNT(DISTINCT cve_id) >= 50  -- Filter for CWEs that appear frequently in combinations
)
SELECT 
    cr.cwe_id,
    cr.name AS cwe_name,
    cr.description,
    cr.weakness_abstraction,
    cr.status,
    COUNT(DISTINCT cs.cve_id) AS occurrence_count
FROM cwe_ref cr
JOIN frequent_cwes_in_combinations fc ON cr.cwe_id = fc.cwe_id
JOIN cwe_split cs ON cr.cwe_id = cs.cwe_id
GROUP BY cr.cwe_id, cr.name, cr.description, cr.weakness_abstraction, cr.status
ORDER BY occurrence_count DESC;
```

* **Superset Chart Type**: Table  
* **Superset Configuration**:  
  * **Columns**: cwe_id, cwe_name, description

### **Ch4_Fig_4.13_Distribution of CWEs by status and abstraction level**

* **Question Answered**: How has the maturity (status) and specificity (abstraction level) of CWEs evolved over time?  
* **SQL Query**: (This query joins cve_main with cwe_ref to get temporal context for CWE status/abstraction.)  
```sql
WITH cwe_split AS (
    SELECT 
        cve_id,
        date_published,
        TRIM(UNNEST(STRING_SPLIT(cwe_ids, ','))) as cwe_id
    FROM cve_main 
    WHERE cwe_ids IS NOT NULL 
        AND cwe_ids != ''
        AND state = 'PUBLISHED'
        AND date_published <= '2025-05-13'
        AND date_published >= '1999-01-01'
),
yearly_cwe_characteristics AS (
    SELECT 
        STRFTIME(cs.date_published, '%Y') AS year,
        cr.status,
        cr.weakness_abstraction,
        COUNT(DISTINCT cs.cve_id) AS cve_count
    FROM cwe_split cs
    JOIN cwe_ref cr ON cs.cwe_id = cr.cwe_id
    WHERE cs.cwe_id LIKE 'CWE-%'
        AND cr.status IS NOT NULL 
        AND cr.status != ''
        AND cr.weakness_abstraction IS NOT NULL 
        AND cr.weakness_abstraction != ''
    GROUP BY year, cr.status, cr.weakness_abstraction
)
SELECT 
    year,
    status,
    weakness_abstraction,
    cve_count,
    CONCAT(status, ' - ', weakness_abstraction) AS status_abstraction_label
FROM yearly_cwe_characteristics
ORDER BY year, cve_count DESC;
```

* **Superset Chart Type**: Stacked Bar Chart or Line Chart  
* **Superset Configuration**:  
  * **X-axis**: year  
  * **Y-axis**: cve_count  
  * **Stack By**: status or weakness_abstraction (create two charts if you want both)  
  * **Time Range**: Custom, e.g., 1999-01-01 to 2025-05-13

## **Exploits**

### **Ch4_Tab_4.9_Overview of the ExploitDB dataset**

* **Question Answered**: How many exploit records are in the dataset?  
* **SQL Query**:  
```sql
SELECT 
    COUNT(id) AS total_exploit_records,
    COUNT(DISTINCT cve_id) AS unique_cves_with_exploits,
    COUNT(CASE WHEN verified = 1 THEN 1 END) AS verified_exploits,
    COUNT(CASE WHEN verified = 0 THEN 1 END) AS unverified_exploits,
    MIN(date_published) AS earliest_exploit_date,
    MAX(date_published) AS latest_exploit_date,
    COUNT(DISTINCT type) AS unique_exploit_types,
    COUNT(DISTINCT platform) AS unique_platforms
FROM exploits 
WHERE date_published <= '2025-05-13';
```

* **Superset Chart Type**: Big Number  
* **Superset Configuration**:  
  * **Metric**: COUNT(exploit_id)

### **Ch4_Fig_4.14_Annual distribution of published exploits with their status**

* **Question Answered**: How has the number of published exploits (verified and unverified) changed over the years?  
* **SQL Query**:  
```sql
SELECT 
    STRFTIME(date_published, '%Y') AS year,
    CASE 
        WHEN verified = 1 THEN 'Verified'
        ELSE 'Unverified'
    END AS verification_status,
    COUNT(exploit_id) AS exploit_count
FROM exploits 
WHERE date_published <= '2025-05-13'
    AND date_published >= '1999-01-01'
GROUP BY year, verification_status
ORDER BY year, verification_status;
```

* **Superset Chart Type**: Stacked Bar Chart or Line Chart  
* **Superset Configuration**:  
  * **X-axis**: year  
  * **Y-axis**: exploit_count  
  * **Stack By / Group By**: verification_status  
  * **Time Range**: Custom, e.g., 1999-01-01 to 2025-05-13

### **Ch4_Fig_4.15_Distribution of Exploit types and their status**

* **Question Answered**: What are the most common types of exploits, and what is their verification status?  
* **SQL Query**:  
```sql
SELECT 
    type AS exploit_type,
    CASE 
        WHEN verified = 1 THEN 'Verified'
        ELSE 'Unverified'
    END AS verification_status,
    COUNT(id) AS exploit_count
FROM exploits 
WHERE type IS NOT NULL 
    AND type != ''
    AND date_published <= '2025-05-13'
GROUP BY exploit_type, verification_status
ORDER BY exploit_count DESC;
```

* **Superset Chart Type**: Stacked Bar Chart (Horizontal)  
* **Superset Configuration**:  
  * **X-axis**: exploit_count  
  * **Y-axis**: exploit_type  
  * **Stack By**: verification_status  
  * **Sort By**: exploit_count (Descending)

### **Ch4_Fig_4.16_Number of CVEs categorized by number of Exploits**

* **Question Answered**: How many exploits are typically associated with a single CVE?  
* **SQL Query**:  
```sql
WITH cve_main_exploit_counts AS (
    -- This CTE establishes the "source of truth" from the 'cve_main' table.
    -- It counts how many exploits each published CVE has *based on available exploit records*.
    -- Crucially, it includes CVEs even if they have zero associated exploits.
    SELECT
        cm.cve_id,
        -- COUNT(ex.exploit_id) counts non-NULL exploit IDs.
        -- If a CVE from cve_main has no match in 'exploits' table (due to LEFT JOIN),
        -- ex.exploit_id will be NULL, resulting in 0 for num_exploits.
        COUNT(ex.id) AS num_exploits_from_cve_main_perspective
    FROM
        cve_main cm
    LEFT JOIN
        exploits ex ON cm.cve_id = ex.cve_id -- LEFT JOIN to keep all published CVEs.
    WHERE
        cm.state = 'PUBLISHED'
        AND cm.date_published <= '2025-07-31' -- Use CURRENT_DATE or a specific date if preferred.
    GROUP BY
        cm.cve_id
),
exploits_table_cve_counts AS (
    -- This CTE establishes the "source of truth" from the 'exploits' table.
    -- It counts how many *exploit records* each CVE has, but *only for CVEs that
    -- actually appear in the 'exploits' table*.
    -- CVEs with zero exploits will NOT appear in this CTE.
    SELECT
        e.cve_id,
        -- COUNT(*) counts all rows for each CVE_ID from the 'exploits' table.
        -- This directly gives the number of exploit records associated with that CVE.
        COUNT(*) AS num_exploits_from_exploits_perspective
    FROM
        exploits e
    WHERE
        e.cve_id IS NOT NULL AND e.cve_id != '' -- Ensure valid CVE IDs from exploits table.
    GROUP BY
        e.cve_id
)
-- Now, we'll combine the results to get the desired comparison.
SELECT
    -- This represents the "category" for the number of exploits.
    -- We get this from the cve_main_exploit_counts to ensure '0' is included.
    COALESCE(cm_counts.num_exploits_from_cve_main_perspective, ex_counts.num_exploits_from_exploits_perspective) AS number_of_exploits,

    -- Column for the number of CVEs as per the 'cve_main' source of truth.
    -- This counts how many *published CVEs* fall into each 'number_of_exploits' category.
    COUNT(DISTINCT cm_counts.cve_id) AS cve_count_from_cve_main,

    -- Column for the number of CVEs as per the 'exploits' table source of truth.
    -- This counts how many *CVEs that have at least one exploit record* fall into
    -- each 'number_of_exploits' category.
    -- Note: This will only count CVEs that actually have exploit entries.
    COUNT(DISTINCT ex_counts.cve_id) AS cve_count_from_exploits_table
FROM
    cve_main_exploit_counts cm_counts
FULL OUTER JOIN -- A FULL OUTER JOIN is used here to ensure we capture all CVE IDs
                -- from both perspectives, especially if there's a CVE in 'exploits'
                -- that somehow isn't in 'cve_main' (though ideally it should be)
                -- or vice-versa for the 'num_exploits' values.
    exploits_table_cve_counts ex_counts
    ON cm_counts.cve_id = ex_counts.cve_id
GROUP BY
    -- We group by the number of exploits. The COALESCE ensures we use the
    -- exploit count from either source if one is NULL after the FULL OUTER JOIN.
    COALESCE(cm_counts.num_exploits_from_cve_main_perspective, ex_counts.num_exploits_from_exploits_perspective)
ORDER BY
    COALESCE(cm_counts.num_exploits_from_cve_main_perspective, ex_counts.num_exploits_from_exploits_perspective) ASC;
```

* **Superset Chart Type**: Bar Chart  
* **Superset Configuration**:  
  * **X-axis**: exploit_count  
  * **Y-axis**: cve_count

### **Ch4_Fig_4.17_Number of CVEs with One Exploit vs More than One Exploit**

* **Question Answered**: What is the proportion of CVEs with a single exploit versus multiple exploits?  
* **SQL Query**:  
```sql
WITH cve_main_exploit_classification AS (
    SELECT
        cm.cve_id,
        COUNT(ex.id) AS num_exploits_for_cve_main,
        CASE
            WHEN COUNT(ex.id) = 1 THEN 'Single Exploit'
            WHEN COUNT(ex.id) > 1 THEN 'Multiple Exploits'
            WHEN COUNT(ex.id) = 0 THEN 'No Public Exploits'
            ELSE 'Unknown'
        END AS category_from_cve_main_perspective
    FROM
        cve_main cm
    LEFT JOIN
        exploits ex ON cm.cve_id = ex.cve_id
    WHERE
        cm.state = 'PUBLISHED'
        AND cm.date_published <= '2025-07-31'
    GROUP BY
        cm.cve_id
),
exploits_table_cve_classification AS (
    SELECT
        e.cve_id,
        COUNT(*) AS num_exploits_for_exploits_table,
        CASE
            WHEN COUNT(*) = 1 THEN 'Single Exploit'
            WHEN COUNT(*) > 1 THEN 'Multiple Exploits'
            ELSE 'Unknown'
        END AS category_from_exploits_table_perspective
    FROM
        exploits e
    WHERE
        e.cve_id IS NOT NULL AND e.cve_id != ''
    GROUP BY
        e.cve_id
)
SELECT
    COALESCE(cm_class.category_from_cve_main_perspective, ex_class.category_from_exploits_table_perspective) AS exploit_category,
    COUNT(DISTINCT cm_class.cve_id) AS cve_count_from_cve_main,
    COUNT(DISTINCT ex_class.cve_id) AS cve_count_from_exploits_table
FROM
    cve_main_exploit_classification cm_class
FULL OUTER JOIN
    exploits_table_cve_classification ex_class
    ON cm_class.cve_id = ex_class.cve_id
GROUP BY
    COALESCE(cm_class.category_from_cve_main_perspective, ex_class.category_from_exploits_table_perspective)
ORDER BY
    CASE COALESCE(cm_class.category_from_cve_main_perspective, ex_class.category_from_exploits_table_perspective)
        WHEN 'No Public Exploits' THEN 1
        WHEN 'Single Exploit' THEN 2
        WHEN 'Multiple Exploits' THEN 3
        ELSE 4
    END;
```

* **Superset Chart Type**: Pie Chart / Donut Chart  
* **Superset Configuration**:  
  * **Group By**: exploit_category  
  * **Metrics**: COUNT(cve_id)

### **Ch4_Fig_4.18_Exploitation rates of CPEs for major vendors**

* **Question Answered**: What are the vulnerability exploitation rates for major software vendors?  
* **SQL Query**:  
```sql
WITH cpe_split AS (
    SELECT
        cve_id,
        has_exploit,
        TRIM(UNNEST(STRING_SPLIT(cpes, ','))) as cpe_entry
    FROM cve_main
    WHERE cpes IS NOT NULL
        AND cpes != ''
        AND state = 'PUBLISHED'
        AND date_published <= '2025-07-31' -- Updated date to current
),
vendor_cve_mapping AS (
    SELECT
        cve_id,
        has_exploit,
        -- This CASE statement handles both CPE 2.3 and CPE 2.2 formats.
        -- For CPE 2.3 (cpe:2.3:...) the vendor is the 4th part.
        -- For CPE 2.2 (cpe:/a:...) or (cpe:/o:...) the vendor is the 3rd part.
        -- We're looking for the component right after 'cpe:version:' or 'cpe:/category:'.
        LOWER(
            CASE
                WHEN cpe_entry LIKE 'cpe:2.3:%' THEN SPLIT_PART(cpe_entry, ':', 4) -- CPE 2.3 format
                WHEN cpe_entry LIKE 'cpe:/%:%' THEN SPLIT_PART(cpe_entry, ':', 3) -- CPE 2.2 format (e.g., cpe:/a:microsoft:...)
                ELSE NULL -- Fallback for unexpected formats
            END
        ) as vendor
    FROM cpe_split
    WHERE cpe_entry LIKE 'cpe:%' -- Ensure it's a valid CPE string
),
vendor_clean AS (
    SELECT
        cve_id,
        has_exploit,
        TRIM(vendor) as vendor
    FROM vendor_cve_mapping
    WHERE vendor IS NOT NULL
        AND vendor != ''
        AND vendor != '*' -- Exclude wildcard vendors
        AND LENGTH(vendor) > 1 -- Exclude single-character vendors which are often placeholders
),
vendor_exploitation_stats AS (
    SELECT
        vendor,
        COUNT(DISTINCT cve_id) AS total_cves,
        COUNT(DISTINCT CASE WHEN has_exploit = 1 THEN cve_id END) AS exploited_cves
    FROM vendor_clean
    GROUP BY vendor
    HAVING COUNT(DISTINCT cve_id) >= 100 -- Filter vendors with significant CVE counts
)
SELECT
    vendor,
    total_cves,
    exploited_cves,
    ROUND(exploited_cves * 100.0 / total_cves, 2) AS exploitation_rate
FROM vendor_exploitation_stats
ORDER BY total_cves DESC
LIMIT 15;
```

* **Superset Chart Type**: Bar Chart (Horizontal)  
* **Superset Configuration**:  
  * **X-axis**: exploitation_rate  
  * **Y-axis**: vendor_name  
  * **Sort By**: exploitation_rate (Descending)  
  * **Limit**: 10

### **Ch4_Fig_4.19_Timeline of exploited CVEs for the top 10 vendors** `Not Match`

* **Question Answered**: How has the number of exploited CVEs for the top 10 vendors changed over time?  
* **SQL Query**:  
```sql
WITH cpe_split AS (
    SELECT 
        cve_id,
        date_published,
        has_exploit,
        TRIM(UNNEST(STRING_SPLIT(cpes, ','))) as cpe_entry
    FROM cve_main 
    WHERE cpes IS NOT NULL 
        AND cpes != ''
        AND state = 'PUBLISHED'
        AND date_published <= '2025-05-13'
        AND date_published >= '1999-01-01'
),
vendor_cve_mapping AS (
    SELECT
        cve_id,
        date_published,
        has_exploit,
        LOWER(
            CASE
                WHEN cpe_entry LIKE 'cpe:2.3:%' THEN SPLIT_PART(cpe_entry, ':', 4)
                WHEN cpe_entry LIKE 'cpe:/%:%' THEN SPLIT_PART(cpe_entry, ':', 3)
                ELSE NULL
            END
        ) as vendor
    FROM cpe_split
    WHERE cpe_entry LIKE 'cpe:%'
),
vendor_clean AS (
    SELECT 
        cve_id,
        date_published,
        has_exploit,
        LOWER(TRIM(vendor)) as vendor
    FROM vendor_cve_mapping
    WHERE vendor IS NOT NULL 
        AND vendor != ''
        AND vendor != '*'
        AND LENGTH(vendor) > 1
),
top_exploited_vendors AS (
    SELECT 
        vendor
    FROM vendor_clean
    WHERE has_exploit = 1
    GROUP BY vendor
    ORDER BY COUNT(DISTINCT cve_id) DESC
    LIMIT 10
),
yearly_vendor_exploits AS (
    SELECT 
        STRFTIME(date_published, '%Y') AS year,
        vendor,
        COUNT(DISTINCT cve_id) AS exploited_cve_count
    FROM vendor_clean
    WHERE has_exploit = 1
        AND vendor IN (SELECT vendor FROM top_exploited_vendors)
    GROUP BY year, vendor
)
SELECT 
    year,
    vendor,
    exploited_cve_count
FROM yearly_vendor_exploits
ORDER BY year, exploited_cve_count DESC;
```

* **Superset Chart Type**: Line Chart  
* **Superset Configuration**:  
  * **X-axis**: year  
  * **Y-axis**: exploited_cve_count  
  * **Group By**: vendor_name  
  * **Time Range**: Custom, e.g., 1999-01-01 to 2025-05-13

### **Ch4_Fig_4.20_Illustration of the many-to-many relationship between CVEs and CPEs**

* **Question Answered**: How does the many-to-many relationship between CVEs and CPEs affect vendor vulnerability counts?  
* **Superset Chart Type**: Not applicable. This is a conceptual diagram, not a direct data visualization.

### **Ch4_Fig_4.21_Data processing workflow for vendor exploitation analysis**

* **Question Answered**: What is the methodology for analyzing vendor exploitation rates?  
* **Superset Chart Type**: Not applicable. This is a conceptual diagram, not a direct data visualization.

### **Ch4_Fig_4.22_Timeline of non-exploited CVEs for the top 10 vendors** `Not Match`

* **Question Answered**: What is the trend for non-exploited vulnerabilities for the top 10 vendors?  
* **SQL Query**:  
```sql
WITH cpe_split AS (
    SELECT 
        cve_id,
        date_published,
        has_exploit,
        TRIM(UNNEST(STRING_SPLIT(cpes, ','))) as cpe_entry
    FROM cve_main 
    WHERE cpes IS NOT NULL 
        AND cpes != ''
        AND state = 'PUBLISHED'
        AND date_published <= '2025-05-13'
        AND date_published >= '1999-01-01'
),
vendor_cve_mapping AS (
    SELECT
        cve_id,
        date_published,
        has_exploit,
        LOWER(
            CASE
                WHEN cpe_entry LIKE 'cpe:2.3:%' THEN SPLIT_PART(cpe_entry, ':', 4)
                WHEN cpe_entry LIKE 'cpe:/%:%' THEN SPLIT_PART(cpe_entry, ':', 3)
                ELSE NULL
            END
        ) as vendor
    FROM cpe_split
    WHERE cpe_entry LIKE 'cpe:%'
),
vendor_clean AS (
    SELECT 
        cve_id,
        date_published,
        has_exploit,
        LOWER(TRIM(vendor)) as vendor
    FROM vendor_cve_mapping
    WHERE vendor IS NOT NULL 
        AND vendor != ''
        AND vendor != '*'
        AND LENGTH(vendor) > 1
),
top_non_exploited_vendors AS (
    SELECT 
        vendor
    FROM vendor_clean
    WHERE has_exploit = 0
    GROUP BY vendor
    ORDER BY COUNT(DISTINCT cve_id) DESC
    LIMIT 10
),
yearly_vendor_non_exploits AS (
    SELECT 
        STRFTIME(date_published, '%Y') AS year,
        vendor,
        COUNT(DISTINCT cve_id) AS non_exploited_cve_count
    FROM vendor_clean
    WHERE has_exploit = 0
        AND vendor IN (SELECT vendor FROM top_non_exploited_vendors)
    GROUP BY year, vendor
)
SELECT 
    year,
    vendor,
    non_exploited_cve_count
FROM yearly_vendor_non_exploits
ORDER BY year, non_exploited_cve_count DESC;
```

* **Superset Chart Type**: Line Chart  
* **Superset Configuration**:  
  * **X-axis**: year  
  * **Y-axis**: non_exploited_cve_count  
  * **Group By**: vendor_name  
  * **Time Range**: Custom, e.g., 1999-01-01 to 2025-05-13

### **Ch4_Tab_4.10_CVEs with their number of exploits, CVSS scores, and relevant dates**

* **Question Answered**: What are the characteristics of CVEs that have a very high number of associated exploits?  
* **SQL Query**:  
```sql
WITH high_exploit_cves AS (
    SELECT 
        cm.cve_id,
        cm.exploit_count,
        cm.cvss_v3_score,
        cm.cvss_v2_score,
        cm.date_reserved,
        cm.date_published,
        cm.cwe_ids,
        cm.kev_known_exploited,
        cm.epss_score
    FROM cve_main cm
    WHERE cm.exploit_count > 5  -- Focus on CVEs with high exploit counts
        AND cm.state = 'PUBLISHED'
        AND cm.date_published <= '2025-05-13'
),
exploit_details AS (
    SELECT 
        hec.cve_id,
        hec.exploit_count,
        hec.cvss_v3_score,
        hec.cvss_v2_score,
        hec.date_reserved,
        hec.date_published,
        hec.cwe_ids,
        hec.kev_known_exploited,
        hec.epss_score,
        MIN(e.date_added) AS first_exploit_date,
        MAX(e.date_updated) AS latest_exploit_update,
        STRING_AGG(DISTINCT e.author, ', ') AS author,
        STRING_AGG(DISTINCT e.platform, ', ') AS platform,
        STRING_AGG(DISTINCT e.type, ', ') AS exploit_types
    FROM high_exploit_cves hec
    LEFT JOIN exploits e ON hec.cve_id = e.cve_id
    GROUP BY hec.cve_id, hec.exploit_count, hec.cvss_v3_score, hec.cvss_v2_score, 
             hec.date_reserved, hec.date_published, hec.cwe_ids, hec.kev_known_exploited, hec.epss_score
)
SELECT 
    cve_id,
    exploit_count,
    cvss_v3_score,
    cvss_v2_score,
    ROUND(epss_score, 4) AS epss_score,
    kev_known_exploited,
    date_reserved,
    date_published,
    first_exploit_date,
    latest_exploit_update,
    exploit_types,
    author,
    platform,
    cwe_ids
FROM exploit_details
ORDER BY exploit_count DESC, cvss_v3_score DESC
LIMIT 20;
```

* **Superset Chart Type**: Table  
* **Superset Configuration**:  
  * **Columns**: cve_id, exploit_count, exploit_date, author, platform, exploit_type, cvss_score, cve_reserved_date, cwe_ids

### **Ch4_Fig_4.23_Distribution of CVE Consistency**
* **Question Answered**: What is the consistency pattern in CVE reporting and classification??  
* **SQL Query**: 
```sql
WITH cve_consistency_metrics AS (
    SELECT 
        cve_id,
        CASE 
            WHEN cwe_ids IS NOT NULL AND cwe_ids != '' THEN 1 ELSE 0 
        END AS has_cwe,
        CASE 
            WHEN cvss_v3_score IS NOT NULL AND cvss_v3_score != -1 THEN 1 ELSE 0 
        END AS has_cvss_v3,
        CASE 
            WHEN cvss_v2_score IS NOT NULL AND cvss_v2_score != -1 THEN 1 ELSE 0 
        END AS has_cvss_v2,
        CASE 
            WHEN cpes IS NOT NULL AND cpes != '' THEN 1 ELSE 0 
        END AS has_cpe,
        CASE 
            WHEN 'references' IS NOT NULL AND 'references' != '' THEN 1 ELSE 0 
        END AS has_references
    FROM cve_main 
    WHERE state = 'PUBLISHED'
        AND date_published <= '2025-05-13'
),
consistency_scores AS (
    SELECT 
        cve_id,
        (has_cwe + has_cvss_v3 + has_cvss_v2 + has_cpe + has_references) AS completeness_score
    FROM cve_consistency_metrics
)
SELECT 
    completeness_score,
    COUNT(cve_id) AS cve_count,
    ROUND(COUNT(cve_id) * 100.0 / SUM(COUNT(cve_id)) OVER (), 2) AS percentage
FROM consistency_scores
GROUP BY completeness_score
ORDER BY completeness_score;
```
## **Patches**



### **Ch4_Fig_4.24_Data processing workflow for product family vulnerability analysis**

* **Question Answered**: What is the methodology for analyzing vulnerability distribution across Microsoft product families?  
* **Superset Chart Type**: Not applicable. This is a conceptual diagram.

### **Ch4_Fig_4.25_Top 15 Microsoft Products by Number of Patched Vulnerabilities**

* **Question Answered**: Which Microsoft product families receive the most patches?  
* **SQL Query**:  
```sql
SELECT 
    product_name,
    COUNT(DISTINCT cve_id) AS patched_cve_count
FROM msrc_patches 
WHERE product_name IS NOT NULL 
    AND product_name != ''
    AND release_date <= '2025-05-13'
GROUP BY product_name
ORDER BY patched_cve_count DESC
LIMIT 15;
```

* **Superset Chart Type**: Bar Chart (Horizontal)  
* **Superset Configuration**:  
  * **X-axis**: patched_cve_count  
  * **Y-axis**: product_name  
  * **Sort By**: patched_cve_count (Descending)  
  * **Limit**: 15

### **Ch4_Fig_4.25_Multi_Vendor_Top 15 Products by Number of Patched Vulnerabilities (All Vendors)**

* **Question Answered**: Which products across all vendors (Microsoft, Cisco, RedHat, Open-source(GitHub)) receive the most patches?  

```sql
WITH unified_patches AS (
    -- Microsoft Patches
    SELECT 
        cve_id,
        product_name,
        'Microsoft' AS vendor_source,
        release_date AS patch_date
    FROM msrc_patches 
    WHERE release_date <= '2025-05-13'
        AND product_name IS NOT NULL 
        AND product_name != ''
    
    UNION ALL
    
    -- Red Hat Patches (filtered for official Red Hat products)
    SELECT 
        cve_id,
        product_name,
        'RedHat' AS vendor_source,
        current_release_date AS patch_date
    FROM redhat_patches 
    WHERE current_release_date <= '2025-05-13'
        AND product_name IS NOT NULL 
        AND product_name != ''
        AND (
            LOWER(product_name) LIKE '%rh%' OR
            LOWER(product_name) LIKE '%red hat%' OR
            LOWER(product_name) LIKE '%red-hat%' OR
            LOWER(product_name) LIKE '%rhel%' OR
            LOWER(product_name) LIKE '%enterprise linux%' OR
            LOWER(product_name) LIKE '%baseos%' OR
            LOWER(product_name) LIKE '%appstream%' OR
            LOWER(product_name) LIKE '%openshift%' OR
            LOWER(product_id) LIKE '%rh%' OR
            LOWER(product_id) LIKE '%red hat%' OR
            LOWER(product_id) LIKE '%red-hat%' OR
            LOWER(product_id) LIKE '%rhel%' OR
            LOWER(product_id) LIKE '%enterprise linux%' OR
            LOWER(product_id) LIKE '%baseos%' OR
            LOWER(product_id) LIKE '%appstream%' OR
            LOWER(product_id) LIKE '%openshift%'
        )
    
    UNION ALL
    
    -- Cisco Patches
    SELECT 
        cve_id,
        product_name,
        'Cisco' AS vendor_source,
        current_release_date AS patch_date
    FROM cisco_patches 
    WHERE current_release_date <= '2025-05-13'
        AND product_name IS NOT NULL 
        AND product_name != ''
    
    UNION ALL
    
    -- GitHub Advisories
    SELECT 
        primary_cve AS cve_id,
        package_name AS product_name,
        'GitHub' AS vendor_source,
        published AS patch_date
    FROM github_advisories 
    WHERE (patched = 1 OR patch_available = 1)
        AND published <= '2025-05-13'
        AND package_name IS NOT NULL 
        AND package_name != ''
        AND primary_cve IS NOT NULL 
        AND primary_cve != ''
)
SELECT 
    product_name,
    vendor_source,
    COUNT(DISTINCT cve_id) AS patched_cve_count
FROM unified_patches
GROUP BY product_name, vendor_source
ORDER BY patched_cve_count DESC
LIMIT 15;
```

### **Ch4_Fig_4.26_Data processing workflow for CWE distribution analysis**

* **Question Answered**: What is the methodology for analyzing the distribution of CWEs in Microsoft patches?  
* **Superset Chart Type**: Not applicable. This is a conceptual diagram.

### **Ch4_Fig_4.27_Top 10 CWEs by Number of Microsoft Patches**

* **Question Answered**: What are the most common weakness types (CWEs) addressed by Microsoft patches?  
* **SQL Query**:  
```sql
WITH microsoft_cwe_split AS (
    SELECT 
        cve_id,
        TRIM(UNNEST(STRING_SPLIT(cwe_ids, ','))) as cwe_id
    FROM msrc_patches 
    WHERE cwe_ids IS NOT NULL 
        AND cwe_ids != ''
        AND release_date <= '2025-05-13'
),
microsoft_cwe_counts AS (
    SELECT 
        mcs.cwe_id,
        COUNT(DISTINCT mcs.cve_id) AS patched_cve_count
    FROM microsoft_cwe_split mcs
    WHERE mcs.cwe_id LIKE 'CWE-%'
    GROUP BY mcs.cwe_id
)
SELECT 
    mcc.cwe_id,
    cr.name AS cwe_name,
    mcc.patched_cve_count
FROM microsoft_cwe_counts mcc
LEFT JOIN cwe_ref cr ON mcc.cwe_id = cr.cwe_id
ORDER BY mcc.patched_cve_count DESC
LIMIT 10;
```

* **Superset Chart Type**: Bar Chart (Horizontal)  
* **Superset Configuration**:  
  * **X-axis**: patched_cve_count  
  * **Y-axis**: cwe_name  
  * **Sort By**: patched_cve_count (Descending)  
  * **Limit**: 10

### **Ch4_Fig_4.27_Multi_Vendor_Top 10 CWEs by Number of Patches (Microsoft, Cisco, RedHat)**

* **Question Answered**: What are the most common weakness types (CWEs) addressed by patches across Microsoft, Cisco, and RedHat??  
* **SQL Query**:  

```sql
WITH cisco_cves_with_cwe AS (
    SELECT 
        cp.cve_id,
        cm.cwe_ids
    FROM cisco_patches cp
    JOIN cve_main cm ON cp.cve_id = cm.cve_id
    JOIN (
        SELECT 
            cve_id
        FROM cve_main
        CROSS JOIN UNNEST(STRING_SPLIT(cpes, ',')) AS cpe_unnest(cpe_entry)
        WHERE LOWER(SPLIT_PART(cpe_entry, ':', 4)) LIKE '%cisco%'
    ) cisco_filter ON cp.cve_id = cisco_filter.cve_id
    WHERE cp.current_release_date <= '2025-05-13'
        AND cm.cwe_ids IS NOT NULL 
        AND cm.cwe_ids != ''
        AND cm.state = 'PUBLISHED'
),
unified_patches_cwe AS (
    -- Microsoft Patches
    SELECT 
        cve_id,
        cwe_ids,
        'Microsoft' AS vendor_source
    FROM msrc_patches 
    WHERE release_date <= '2025-05-13'
        AND cwe_ids IS NOT NULL 
        AND cwe_ids != ''
    
    UNION ALL
    
    -- Red Hat Patches (filtered for official Red Hat products)
    SELECT 
        cve_id,
        cwe_id AS cwe_ids,
        'RedHat' AS vendor_source
    FROM redhat_patches 
    WHERE current_release_date <= '2025-05-13'
        AND cwe_id IS NOT NULL 
        AND cwe_id != ''
        AND (
            LOWER(product_name) LIKE '%rh%' OR
            LOWER(product_name) LIKE '%red hat%' OR
            LOWER(product_name) LIKE '%red-hat%' OR
            LOWER(product_name) LIKE '%rhel%' OR
            LOWER(product_name) LIKE '%enterprise linux%' OR
            LOWER(product_name) LIKE '%baseos%' OR
            LOWER(product_name) LIKE '%appstream%' OR
            LOWER(product_name) LIKE '%openshift%' OR
            LOWER(product_id) LIKE '%rh%' OR
            LOWER(product_id) LIKE '%red hat%' OR
            LOWER(product_id) LIKE '%red-hat%' OR
            LOWER(product_id) LIKE '%rhel%' OR
            LOWER(product_id) LIKE '%enterprise linux%' OR
            LOWER(product_id) LIKE '%baseos%' OR
            LOWER(product_id) LIKE '%appstream%' OR
            LOWER(product_id) LIKE '%openshift%'
        )
    
    UNION ALL
    
    -- Cisco Patches (fallback to cve_main for CWE data)
    SELECT 
        cve_id,
        cwe_ids,
        'Cisco' AS vendor_source
    FROM cisco_cves_with_cwe
),
multi_vendor_cwe_split AS (
    SELECT 
        cve_id,
        vendor_source,
        TRIM(UNNEST(STRING_SPLIT(cwe_ids, ','))) as cwe_id
    FROM unified_patches_cwe
),
multi_vendor_cwe_counts AS (
    SELECT 
        mcs.cwe_id,
        COUNT(DISTINCT mcs.cve_id) AS total_patched_cves,
        STRING_AGG(DISTINCT mcs.vendor_source, ', ') AS contributing_vendors
    FROM multi_vendor_cwe_split mcs
    WHERE mcs.cwe_id LIKE 'CWE-%'
    GROUP BY mcs.cwe_id
)
SELECT 
    mcc.cwe_id,
    cr.name AS cwe_name,
    mcc.total_patched_cves,
    mcc.contributing_vendors
FROM multi_vendor_cwe_counts mcc
LEFT JOIN cwe_ref cr ON mcc.cwe_id = cr.cwe_id
ORDER BY mcc.total_patched_cves DESC
LIMIT 10;
```
### **Ch4_Fig_4.28_Trends of Top 5 CWE Patches Over Time**

* **Question Answered**: How has the patching frequency for the top 5 CWEs in Microsoft products changed over time?  
* **SQL Query**: (Assuming top 5 CWEs are identified from a previous step, e.g., CWE-787, CWE-416, CWE-119, CWE-200, CWE-20)  
```sql
WITH microsoft_cwe_split AS (
    SELECT 
        cve_id,
        release_date,
        TRIM(UNNEST(STRING_SPLIT(cwe_ids, ','))) as cwe_id
    FROM msrc_patches 
    WHERE cwe_ids IS NOT NULL 
        AND cwe_ids != ''
        AND release_date <= '2025-05-13'
        AND release_date >= '2016-01-01'
),
top_5_microsoft_cwes AS (
    SELECT 
        cwe_id,
        COUNT(DISTINCT cve_id) as patch_count
    FROM microsoft_cwe_split
    WHERE cwe_id LIKE 'CWE-%'
    GROUP BY cwe_id
    ORDER BY patch_count DESC
    LIMIT 5
),
yearly_cwe_trends AS (
    SELECT 
        STRFTIME(mcs.release_date, '%Y') AS year,
        mcs.cwe_id,
        COUNT(DISTINCT mcs.cve_id) AS patched_cve_count
    FROM microsoft_cwe_split mcs
    WHERE mcs.cwe_id IN (SELECT cwe_id FROM top_5_microsoft_cwes)
    GROUP BY year, mcs.cwe_id
)
SELECT 
    yct.year,
    yct.cwe_id,
    cr.name AS cwe_name,
    yct.patched_cve_count
FROM yearly_cwe_trends yct
LEFT JOIN cwe_ref cr ON yct.cwe_id = cr.cwe_id
ORDER BY yct.year, yct.patched_cve_count DESC;
```

* **Superset Chart Type**: Line Chart  
* **Superset Configuration**:  
  * **X-axis**: year  
  * **Y-axis**: patched_cve_count  
  * **Group By**: cwe_name  
  * **Time Range**: Custom, e.g., 2016-01-01 to 2025-05-13

### **Ch4_Fig_4.28_Multi_Vendor_Trends of Top 5 CWE Patches Over Time (Microsoft, Cisco, RedHat)**

* **Question Answered**: How has the patching frequency for the top 5 CWEs changed over time across Microsoft, Cisco, and RedHat?  
```sql
WITH cisco_cpe_filter AS (
    SELECT DISTINCT 
        cve_id
    FROM cve_main
    CROSS JOIN UNNEST(STRING_SPLIT(cpes, ',')) AS cpe_unnest(cpe_entry)
    WHERE LOWER(SPLIT_PART(cpe_entry, ':', 4)) = 'cisco'
        AND state = 'PUBLISHED'
        AND date_published >= '2016-01-01'
        AND date_published <= '2025-05-13'
),
microsoft_patch_cwes AS (
    SELECT 
        cve_id,
        release_date as patch_date,
        TRIM(UNNEST(STRING_SPLIT(cwe_ids, ','))) as cwe_id,
        'Microsoft' AS vendor_source
    FROM msrc_patches 
    WHERE release_date >= '2016-01-01' 
        AND release_date <= '2025-05-13'
        AND cwe_ids IS NOT NULL 
        AND cwe_ids != ''
),
redhat_patch_cwes AS (
    SELECT 
        cve_id,
        current_release_date as patch_date,
        cwe_id,
        'RedHat' AS vendor_source
    FROM redhat_patches 
    WHERE current_release_date >= '2016-01-01'
        AND current_release_date <= '2025-05-13'
        AND cwe_id IS NOT NULL 
        AND cwe_id != ''
        AND (LOWER(product_name) LIKE '%rhel%' OR LOWER(product_name) LIKE '%red hat%' OR LOWER(product_name) LIKE '%enterprise linux%')
),
cisco_patch_cwes AS (
    SELECT 
        cp.cve_id,
        cp.current_release_date as patch_date,
        TRIM(UNNEST(STRING_SPLIT(cm.cwe_ids, ','))) as cwe_id,
        'Cisco' AS vendor_source
    FROM cisco_patches cp
    JOIN cve_main cm ON cp.cve_id = cm.cve_id
    WHERE cp.cve_id IN (SELECT cve_id FROM cisco_cpe_filter)
        AND cp.current_release_date >= '2016-01-01' 
        AND cp.current_release_date <= '2025-05-13'
        AND cm.cwe_ids IS NOT NULL 
        AND cm.cwe_ids != ''
),
unified_patch_cwes AS (
    SELECT * FROM microsoft_patch_cwes
    WHERE cwe_id LIKE 'CWE-%'
    
    UNION ALL
    
    SELECT * FROM redhat_patch_cwes
    WHERE cwe_id LIKE 'CWE-%'
    
    UNION ALL
    
    SELECT * FROM cisco_patch_cwes
    WHERE cwe_id LIKE 'CWE-%'
),
top_5_multi_vendor_cwes AS (
    SELECT 
        cwe_id,
        COUNT(DISTINCT cve_id) as total_patches
    FROM unified_patch_cwes
    GROUP BY cwe_id
    ORDER BY total_patches DESC
    LIMIT 5
),
yearly_multi_vendor_trends AS (
    SELECT 
        STRFTIME(upc.patch_date, '%Y') AS year,
        upc.cwe_id,
        COUNT(DISTINCT upc.cve_id) AS patched_cve_count
    FROM unified_patch_cwes upc
    WHERE upc.cwe_id IN (SELECT cwe_id FROM top_5_multi_vendor_cwes)
    GROUP BY year, upc.cwe_id
)
SELECT 
    ymvt.year,
    ymvt.cwe_id,
    cr.name AS cwe_name,
    ymvt.patched_cve_count
FROM yearly_multi_vendor_trends ymvt
LEFT JOIN cwe_ref cr ON ymvt.cwe_id = cr.cwe_id
ORDER BY ymvt.year, ymvt.patched_cve_count DESC;

```
### **Ch4_Tab_4.11_Comparison of Top CWE Rankings: Microsoft Patches vs. All CVEs**

* **Question Answered**: How does the ranking of top CWEs in Microsoft patches compare to the overall ranking across all CVEs?  
* **SQL Queries**: (This requires two separate queries in Superset, which you can then combine on a dashboard.)  
```sql
WITH microsoft_cwe_ranks AS (
    -- First CTE: Calculate CVE counts and ranks specifically for Microsoft patched CVEs.
    WITH microsoft_cwe_split AS (
        SELECT
            cve_id,
            TRIM(UNNEST(STRING_SPLIT(cwe_ids, ','))) as cwe_id
        FROM msrc_patches
        WHERE cwe_ids IS NOT NULL
            AND cwe_ids != ''
            AND release_date <= '2025-07-31' -- Changed to current date as per previous context
    )
    SELECT
        mcs.cwe_id,
        cr.name AS cwe_name,
        COUNT(DISTINCT mcs.cve_id) AS ms_patched_cve_count,
        ROW_NUMBER() OVER (ORDER BY COUNT(DISTINCT mcs.cve_id) DESC) AS ms_rank
    FROM microsoft_cwe_split mcs
    LEFT JOIN cwe_ref cr ON mcs.cwe_id = cr.cwe_id
    WHERE mcs.cwe_id LIKE 'CWE-%'
    GROUP BY mcs.cwe_id, cr.name
),
all_cve_ranks AS (
    -- Second CTE: Calculate CVE counts and ranks for all published CVEs.
    WITH all_cve_split AS (
        SELECT
            cve_id,
            TRIM(UNNEST(STRING_SPLIT(cwe_ids, ','))) as cwe_id
        FROM cve_main
        WHERE cwe_ids IS NOT NULL
            AND cwe_ids != ''
            AND state = 'PUBLISHED'
            AND date_published <= '2025-07-31' -- Changed to current date as per previous context
    )
    SELECT
        acs.cwe_id,
        cr.name AS cwe_name,
        COUNT(DISTINCT acs.cve_id) AS all_cve_count,
        ROW_NUMBER() OVER (ORDER BY COUNT(DISTINCT acs.cve_id) DESC) AS overall_rank
    FROM all_cve_split acs
    LEFT JOIN cwe_ref cr ON acs.cwe_id = cr.cwe_id
    WHERE acs.cwe_id LIKE 'CWE-%'
    GROUP BY acs.cwe_id, cr.name
)
-- Final SELECT: Join the results from both ranking CTEs.
SELECT
    -- Use COALESCE to ensure cwe_id and cwe_name are present even if a CWE
    -- only appears in one of the top 10 lists.
    COALESCE(mcr.cwe_id, acr.cwe_id) AS cwe_id,
    COALESCE(mcr.cwe_name, acr.cwe_name) AS cwe_name,
    mcr.ms_patched_cve_count,
    mcr.ms_rank,
    acr.all_cve_count,
    acr.overall_rank
FROM
    microsoft_cwe_ranks mcr
FULL OUTER JOIN -- Use FULL OUTER JOIN to include CWEs that are in the top 10 for one list but not the other.
    all_cve_ranks acr ON mcr.cwe_id = acr.cwe_id
WHERE
    -- Filter to include only CWEs that are in the top 10 of *either* list.
    -- Remove this WHERE clause if you want all CWEs that have a rank in either table.
    (mcr.ms_rank <= 10 OR acr.overall_rank <= 10)
ORDER BY
    -- You can choose the primary order. Here, it's ordered by overall_rank first,
    -- then by ms_rank, to prioritize the global top 10, then Microsoft's top 10.
    -- COALESCE handles cases where a rank might be NULL if the CWE isn't in one of the top 10 lists.
    COALESCE(acr.overall_rank, 999999) ASC, -- Sort by overall rank, push non-ranked to end
    COALESCE(mcr.ms_rank, 999999) ASC;      

```

* **Superset Chart Type**: Two separate Tables or Bar Charts. You'd typically compare them side-by-side on a dashboard.  
* **Superset Configuration**:  
  * **For each Table**:  
    * **Columns**: cwe_id, cwe_name, ms_patched_cve_count/all_cve_count, ms_rank/overall_rank

### **Ch4_Tab_4.11_Multi_Vendor_Comparison of Top CWE Rankings: Multi-Vendor Patches vs. All CVEs**

* **Question Answered**: How does the ranking of top CWEs in multi-vendor patches compare to the overall ranking across all CVEs?

* **SQL Queries**: (This requires two separate queries in Superset, which you can then combine on a dashboard.)  
```sql
WITH cisco_cpe_filter AS (
    SELECT DISTINCT cve_id
    FROM cve_main
    CROSS JOIN UNNEST(STRING_SPLIT(cpes, ',')) AS cpe_unnest(cpe_entry)
    WHERE LOWER(SPLIT_PART(cpe_entry, ':', 4)) = 'cisco'
        AND state = 'PUBLISHED'
        AND date_published <= '2025-05-13'
),
microsoft_patch_cwes AS (
    SELECT 
        cve_id,
        TRIM(UNNEST(STRING_SPLIT(cwe_ids, ','))) as cwe_id
    FROM msrc_patches 
    WHERE cwe_ids IS NOT NULL 
        AND cwe_ids != ''
        AND release_date <= '2025-05-13'
),
redhat_patch_cwes AS (
    SELECT 
        cve_id,
        cwe_id
    FROM redhat_patches 
    WHERE cwe_id IS NOT NULL 
        AND cwe_id != ''
        AND current_release_date <= '2025-05-13'
        AND (LOWER(product_name) LIKE '%rhel%' OR LOWER(product_name) LIKE '%red hat%' OR LOWER(product_name) LIKE '%enterprise linux%')
),
cisco_patch_cwes AS (
    SELECT 
        cp.cve_id,
        TRIM(UNNEST(STRING_SPLIT(cm.cwe_ids, ','))) as cwe_id
    FROM cisco_patches cp
    JOIN cve_main cm ON cp.cve_id = cm.cve_id
    WHERE cp.cve_id IN (SELECT cve_id FROM cisco_cpe_filter)
        AND cp.current_release_date <= '2025-05-13'
        AND cm.cwe_ids IS NOT NULL 
        AND cm.cwe_ids != ''
),
unified_patch_cwes AS (
    SELECT cve_id, cwe_id FROM microsoft_patch_cwes WHERE cwe_id LIKE 'CWE-%'
    UNION ALL
    SELECT cve_id, cwe_id FROM redhat_patch_cwes WHERE cwe_id LIKE 'CWE-%'
    UNION ALL
    SELECT cve_id, cwe_id FROM cisco_patch_cwes WHERE cwe_id LIKE 'CWE-%'
),
multi_vendor_cwe_ranks AS (
    SELECT 
        upc.cwe_id,
        cr.name AS cwe_name,
        COUNT(DISTINCT upc.cve_id) AS multi_vendor_patched_count,
        ROW_NUMBER() OVER (ORDER BY COUNT(DISTINCT upc.cve_id) DESC) AS multi_vendor_rank
    FROM unified_patch_cwes upc
    LEFT JOIN cwe_ref cr ON upc.cwe_id = cr.cwe_id
    GROUP BY upc.cwe_id, cr.name
)
SELECT 
    cwe_id,
    cwe_name,
    multi_vendor_patched_count,
    multi_vendor_rank
FROM multi_vendor_cwe_ranks
WHERE multi_vendor_rank <= 10
ORDER BY multi_vendor_rank;
```

### **Ch4_Fig_4.29_Comparative Distribution of Memory Safety vs. Web Vulnerabilities**

* **Question Answered**: How does the focus on memory safety versus web vulnerabilities in Microsoft patches compare to the overall landscape?  
* **SQL Query**: (This query categorizes CWEs and calculates percentages for both datasets.)  
```sql
  WITH microsoft_cwe_split AS (
    SELECT
        cve_id,
        TRIM(UNNEST(STRING_SPLIT(cwe_ids, ','))) as cwe_id
    FROM msrc_patches
    WHERE cwe_ids IS NOT NULL
        AND cwe_ids != ''
        AND release_date <= '2025-07-31' -- Updated date to current
),
ms_cwe_categories AS (
    SELECT
        CASE
            WHEN cwe_id IN ('CWE-119', 'CWE-121', 'CWE-122', 'CWE-125', 'CWE-416', 'CWE-787', 'CWE-190', 'CWE-476', 'CWE-680') THEN 'Memory Safety Issues'
            WHEN cwe_id IN ('CWE-79', 'CWE-89', 'CWE-352', 'CWE-80', 'CWE-77', 'CWE-78') THEN 'Web Vulnerabilities'
            ELSE 'Other'
        END AS cwe_category,
        COUNT(DISTINCT cve_id) AS category_count
    FROM microsoft_cwe_split
    WHERE cwe_id LIKE 'CWE-%'
    GROUP BY cwe_category
),
all_cve_split AS (
    SELECT
        cve_id,
        TRIM(UNNEST(STRING_SPLIT(cwe_ids, ','))) as cwe_id
    FROM cve_main
    WHERE cwe_ids IS NOT NULL
        AND cwe_ids != ''
        AND state = 'PUBLISHED'
        AND date_published <= '2025-07-31' -- Updated date to current
),
all_cve_categories AS (
    SELECT
        CASE
            WHEN cwe_id IN ('CWE-119', 'CWE-121', 'CWE-122', 'CWE-125', 'CWE-416', 'CWE-787', 'CWE-190', 'CWE-476', 'CWE-680') THEN 'Memory Safety Issues'
            WHEN cwe_id IN ('CWE-79', 'CWE-89', 'CWE-352', 'CWE-80', 'CWE-77', 'CWE-78') THEN 'Web Vulnerabilities'
            ELSE 'Other'
        END AS cwe_category,
        COUNT(DISTINCT cve_id) AS category_count
    FROM all_cve_split
    WHERE cwe_id LIKE 'CWE-%'
    GROUP BY cwe_category
)
-- Combine the results using UNION ALL
SELECT
    'Microsoft Patches' AS dataset,
    cwe_category,
    category_count,
    ROUND(category_count * 100.0 / SUM(category_count) OVER (), 2) AS percentage
FROM ms_cwe_categories

UNION ALL

SELECT
    'All CVEs' AS dataset,
    cwe_category,
    category_count,
    ROUND(category_count * 100.0 / SUM(category_count) OVER (), 2) AS percentage
FROM all_cve_categories
ORDER BY dataset, cwe_category; 
```

* **Superset Chart Type**: Grouped Bar Chart  
* **Superset Configuration**:  
  * **X-axis**: cwe_category  
  * **Y-axis**: percentage  
  * **Group By**: dataset  
  * **Chart Options**: Set Y-axis to percentage format.



### **Ch4_Fig_4.30_Severity Distribution of Patched Vulnerabilities for Top 5 Product Families**

* **Question Answered**: What is the severity breakdown of patched vulnerabilities for Microsoft's top product families?  
* **SQL Query**:  
```sql
WITH top_5_ms_products AS (
    SELECT 
        product_name
    FROM msrc_patches 
    WHERE product_name IS NOT NULL 
        AND product_name != ''
        AND release_date <= '2025-05-13'
    GROUP BY product_name
    ORDER BY COUNT(DISTINCT cve_id) DESC
    LIMIT 5
),
ms_product_severity AS (
    SELECT 
        mp.product_name,
        cm.cvss_v3_severity AS severity_level,
        COUNT(DISTINCT mp.cve_id) AS patched_cve_count
    FROM msrc_patches mp
    JOIN cve_main cm ON mp.cve_id = cm.cve_id
    WHERE mp.product_name IN (SELECT product_name FROM top_5_ms_products)
        AND cm.cvss_v3_severity IS NOT NULL 
        AND cm.cvss_v3_severity != ''
        AND cm.cvss_v3_severity IN ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW')
        AND mp.release_date <= '2025-05-13'
    GROUP BY mp.product_name, cm.cvss_v3_severity
)
SELECT 
    product_name,
    severity_level,
    patched_cve_count
FROM ms_product_severity
ORDER BY 
    product_name,
    CASE severity_level 
        WHEN 'CRITICAL' THEN 1 
        WHEN 'HIGH' THEN 2 
        WHEN 'MEDIUM' THEN 3 
        WHEN 'LOW' THEN 4 
    END;
```

* **Superset Chart Type**: Stacked Bar Chart (or Grouped Bar Chart)  
* **Superset Configuration**:  
  * **X-axis**: product_name  
  * **Y-axis**: patched_cve_count  
  * **Stack By**: severity_level

### **Ch4_Fig_4.30_Multi_Vendor_Severity Distribution of Patched Vulnerabilities for Top 5 Products**
```sql
WITH cisco_cpe_filter AS (
    SELECT DISTINCT cve_id
    FROM cve_main
    CROSS JOIN UNNEST(STRING_SPLIT(cpes, ',')) AS cpe_unnest(cpe_entry)
    WHERE LOWER(SPLIT_PART(cpe_entry, ':', 4)) = 'cisco'
        AND state = 'PUBLISHED'
        AND date_published <= '2025-05-13'
),
unified_top_products AS (
    SELECT product_name, 'Microsoft' as vendor, COUNT(DISTINCT cve_id) as patch_count
    FROM msrc_patches 
    WHERE product_name IS NOT NULL AND release_date <= '2025-05-13'
    GROUP BY product_name
    
    UNION ALL
    
    SELECT product_name, 'RedHat' as vendor, COUNT(DISTINCT cve_id) as patch_count
    FROM redhat_patches 
    WHERE product_name IS NOT NULL AND current_release_date <= '2025-05-13'
        AND (LOWER(product_name) LIKE '%rhel%' OR LOWER(product_name) LIKE '%red hat%')
    GROUP BY product_name
    
    UNION ALL
    
    SELECT product_name, 'Cisco' as vendor, COUNT(DISTINCT cve_id) as patch_count
    FROM cisco_patches 
    WHERE product_name IS NOT NULL AND current_release_date <= '2025-05-13'
    GROUP BY product_name
),
top_5_products AS (
    SELECT product_name, vendor
    FROM unified_top_products
    ORDER BY patch_count DESC
    LIMIT 5
),
microsoft_severity AS (
    SELECT 
        mp.product_name,
        'Microsoft' as vendor,
        cm.cvss_v3_severity AS severity_level,
        COUNT(DISTINCT mp.cve_id) AS patched_cve_count
    FROM msrc_patches mp
    JOIN cve_main cm ON mp.cve_id = cm.cve_id
    JOIN top_5_products t5p ON mp.product_name = t5p.product_name AND t5p.vendor = 'Microsoft'
    WHERE cm.cvss_v3_severity IN ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW')
        AND mp.release_date <= '2025-05-13'
    GROUP BY mp.product_name, cm.cvss_v3_severity
),
redhat_severity AS (
    SELECT 
        rp.product_name,
        'RedHat' as vendor,
        cm.cvss_v3_severity AS severity_level,
        COUNT(DISTINCT rp.cve_id) AS patched_cve_count
    FROM redhat_patches rp
    JOIN cve_main cm ON rp.cve_id = cm.cve_id
    JOIN top_5_products t5p ON rp.product_name = t5p.product_name AND t5p.vendor = 'RedHat'
    WHERE cm.cvss_v3_severity IN ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW')
        AND rp.current_release_date <= '2025-05-13'
    GROUP BY rp.product_name, cm.cvss_v3_severity
),
cisco_severity AS (
    SELECT 
        cp.product_name,
        'Cisco' as vendor,
        cm.cvss_v3_severity AS severity_level,
        COUNT(DISTINCT cp.cve_id) AS patched_cve_count
    FROM cisco_patches cp
    JOIN cve_main cm ON cp.cve_id = cm.cve_id
    JOIN top_5_products t5p ON cp.product_name = t5p.product_name AND t5p.vendor = 'Cisco'
    WHERE cm.cvss_v3_severity IN ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW')
        AND cp.current_release_date <= '2025-05-13'
    GROUP BY cp.product_name, cm.cvss_v3_severity
),
multi_vendor_severity AS (
    SELECT * FROM microsoft_severity
    UNION ALL
    SELECT * FROM redhat_severity
    UNION ALL
    SELECT * FROM cisco_severity
)
SELECT 
    CONCAT(product_name, ' (', vendor, ')') as product_vendor,
    severity_level,
    patched_cve_count
FROM multi_vendor_severity
ORDER BY 
    patched_cve_count DESC,
    CASE severity_level 
        WHEN 'CRITICAL' THEN 1 
        WHEN 'HIGH' THEN 2 
        WHEN 'MEDIUM' THEN 3 
        WHEN 'LOW' THEN 4 
    END;
```