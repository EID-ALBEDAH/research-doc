# Chapter 5: Lifecycle Analysis (Enhanced Multi-Vendor)

## Overview

This chapter presents enhanced vulnerability lifecycle analysis building upon the transfer report foundation, now incorporating multi-vendor data and advanced statistical modeling techniques including survival analysis and temporal pattern recognition.

## **Data Preparation Notes:**

* **Date Filtering**: All queries implicitly filter date_published or release_date up to '2025-05-13'. You can adjust this date in Superset's time filter or directly in the SQL.  
* **Unnesting/Splitting**: For columns like cpes, vendors, and cwe_ids which are comma-separated strings, STRING_SPLIT_BY_REGEX is used to convert them into arrays, followed by UNNEST to expand them into separate rows for aggregation.  
* **Patch Data Unification**: For analyses requiring comprehensive patch data across vendors, a UNION ALL approach is used to combine msrc_patches, redhat_patches, cisco_patches, github_advisories, and morefixes_fixes.  
  * **Red Hat Filtering**: Remember to apply the specified Red Hat product filtering (product_name or product_id containing rh, red hat, red-hat, rhel, enterprise linux, baseos, appstream, openshift) for official Red Hat products. This is included in the Red Hat specific queries.  
  * **GitHub Advisories**: github_advisories is included where patched = 1 or patch_available = 1.  
  * **MoreFixes**: morefixes_fixes is joined with morefixes_commits to get the author_date as the patch date.  

<div class="superset-embed">
    <iframe
        width="100%"
        height="100%"
        seamless
        frameBorder="0"
        scrolling="yes"
        src="https://analytic.ifthreat.com/superset/dashboard/chapter-5/?standalone=1&height=1080&show_filters=1"
        loading="lazy">
    </iframe>
    <p class="chart-caption">📊 Chapter 4: Complete CVE Analysis Dashboard - Interactive Multi-Vendor Analysis</p>
</div>
## **Lifecycle Analysis**



### **Ch5_Fig_5.1_Distribution of Vulnerability Lifecycle Events (2016-2025) for Microsoft**

* **Question Answered**: What is the temporal distribution of key vulnerability lifecycle events (disclosure, exploit, patch) for Microsoft?  
* **SQL Query**:  
```sql
WITH microsoft_cves AS (
    SELECT DISTINCT 
        cm.cve_id,
        cm.date_reserved
    FROM cve_main cm
    CROSS JOIN UNNEST(STRING_SPLIT(cm.cpes, ',')) AS cpe_unnest(cpe_entry)
    WHERE LOWER(SPLIT_PART(cpe_entry, ':', 4)) = 'microsoft'
        AND cm.state = 'PUBLISHED'
        AND cm.date_reserved >= '2016-01-01'
        AND cm.date_reserved <= '2025-05-13'
),
lifecycle_events AS (
    SELECT 
        STRFTIME(date_reserved, '%Y') AS year,
        'CVE Reserved' AS event_type,
        COUNT(DISTINCT cve_id) AS event_count
    FROM microsoft_cves
    GROUP BY year, event_type
    
    UNION ALL
    
    SELECT 
        STRFTIME(e.date_added, '%Y') AS year,
        'Exploit Added' AS event_type,
        COUNT(DISTINCT e.cve_id) AS event_count
    FROM exploits e
    WHERE e.cve_id IN (SELECT cve_id FROM microsoft_cves)
        AND e.date_added >= '2016-01-01'
        AND e.date_added <= '2025-05-13'
    GROUP BY year, event_type
    
    UNION ALL
    
    SELECT 
        STRFTIME(mp.initial_release_date, '%Y') AS year,
        'Patch Released' AS event_type,
        COUNT(DISTINCT mp.cve_id) AS event_count
    FROM msrc_patches mp
    WHERE mp.cve_id IN (SELECT cve_id FROM microsoft_cves)
        AND mp.initial_release_date >= '2016-01-01'
        AND mp.initial_release_date <= '2025-05-13'
    GROUP BY year, event_type
)
SELECT 
    year,
    event_type,
    event_count
FROM lifecycle_events
ORDER BY year, event_type;
```

* **Superset Chart Type**: Line Chart  
* **Superset Configuration**:  
  * **X-axis**: year  
  * **Y-axis**: event_count  
  * **Group By**: event_type  
  * **Time Range**: Custom, 2016-01-01 to 2025-05-13

### **Ch5_Fig_5.1_Multi_Vendor_Distribution of Vulnerability Lifecycle Events (2016-2025) for All Vendors**

* **Question Answered**: What is the temporal distribution of key vulnerability lifecycle events (disclosure, exploit, patch) for All vendors?  

```sql
WITH vendor_cves AS (
    SELECT DISTINCT 
        cm.cve_id,
        cm.date_reserved,
        CASE 
            WHEN LOWER(SPLIT_PART(cpe_entry, ':', 4)) = 'microsoft' THEN 'Microsoft'
            WHEN LOWER(SPLIT_PART(cpe_entry, ':', 4)) = 'cisco' THEN 'Cisco'
            WHEN LOWER(SPLIT_PART(cpe_entry, ':', 4)) IN ('redhat', 'red_hat') THEN 'RedHat'
        END AS vendor
    FROM cve_main cm
    CROSS JOIN UNNEST(STRING_SPLIT(cm.cpes, ',')) AS cpe_unnest(cpe_entry)
    WHERE LOWER(SPLIT_PART(cpe_entry, ':', 4)) IN ('microsoft', 'cisco', 'redhat', 'red_hat')
        AND cm.state = 'PUBLISHED'
        AND cm.date_reserved >= '2016-01-01'
        AND cm.date_reserved <= '2025-05-13'
),
multi_vendor_lifecycle_events AS (
    SELECT 
        STRFTIME(vc.date_reserved, '%Y') AS year,
        vc.vendor,
        'CVE Reserved' AS event_type,
        COUNT(DISTINCT vc.cve_id) AS event_count
    FROM vendor_cves vc
    GROUP BY year, vendor, event_type
    
    UNION ALL
    
    SELECT 
        STRFTIME(e.date_published, '%Y') AS year,
        vc.vendor,
        'Exploit Published' AS event_type,
        COUNT(DISTINCT e.cve_id) AS event_count
    FROM exploits e
    JOIN vendor_cves vc ON e.cve_id = vc.cve_id
    WHERE e.date_published >= '2016-01-01' 
        AND e.date_published <= '2025-05-13'
    GROUP BY year, vendor, event_type
    
    UNION ALL
    
    SELECT 
        STRFTIME(mp.initial_release_date, '%Y') AS year,
        'Microsoft' AS vendor,
        'Patch Released' AS event_type,
        COUNT(DISTINCT mp.cve_id) AS event_count
    FROM msrc_patches mp
    JOIN vendor_cves vc ON mp.cve_id = vc.cve_id AND vc.vendor = 'Microsoft'
    WHERE mp.initial_release_date >= '2016-01-01' 
        AND mp.initial_release_date <= '2025-05-13'
    GROUP BY year, vendor, event_type
    
    UNION ALL
    
    SELECT 
        STRFTIME(cp.initial_release_date, '%Y') AS year,
        'Cisco' AS vendor,
        'Patch Released' AS event_type,
        COUNT(DISTINCT cp.cve_id) AS event_count
    FROM cisco_patches cp
    JOIN vendor_cves vc ON cp.cve_id = vc.cve_id AND vc.vendor = 'Cisco'
    WHERE cp.initial_release_date >= '2016-01-01' 
        AND cp.initial_release_date <= '2025-05-13'
    GROUP BY year, vendor, event_type
    
    UNION ALL
    
    SELECT 
        STRFTIME(rp.initial_release_date, '%Y') AS year,
        'RedHat' AS vendor,
        'Patch Released' AS event_type,
        COUNT(DISTINCT rp.cve_id) AS event_count
    FROM redhat_patches rp
    JOIN vendor_cves vc ON rp.cve_id = vc.cve_id AND vc.vendor = 'RedHat'
    WHERE rp.initial_release_date >= '2016-01-01' 
        AND rp.initial_release_date <= '2025-05-13'
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
    GROUP BY year, vendor, event_type
)
SELECT 
    year,
    vendor,
    event_type,
    event_count
FROM multi_vendor_lifecycle_events
ORDER BY year, vendor, event_type;
```


### **Ch5_Fig_5.2_Distribution of exploit publication timing relative to CVE reservation (1999-2025)**

* **Question Answered**: How has the timing of exploit publication relative to CVE disclosure evolved over the years?  
* **SQL Query**:  
```sql
WITH cve_exploit_timing AS (
    SELECT 
        cm.cve_id,
        cm.date_reserved,
        e.date_published as exploit_date,
        STRFTIME(cm.date_reserved, '%Y') AS year,
        CASE 
            WHEN e.date_published < cm.date_reserved THEN 'Pre-CVE Exploit'
            WHEN DATE_DIFF('day', cm.date_reserved, e.date_published) = 0 THEN 'Zero-Day Exploit'
            WHEN e.date_published > cm.date_reserved THEN 'Post-CVE Exploit'
            ELSE 'Unknown'
        END AS exploit_timing_category
    FROM cve_main cm
    JOIN exploits e ON cm.cve_id = e.cve_id
    WHERE cm.state = 'PUBLISHED'
        AND cm.date_reserved >= '1999-01-01'
        AND cm.date_reserved <= '2025-05-13'
        AND e.date_published <= '2025-05-13'
        AND cm.date_reserved IS NOT NULL
        AND e.date_published IS NOT NULL
)
SELECT 
    year,
    exploit_timing_category,
    COUNT(DISTINCT cve_id) AS cve_count
FROM cve_exploit_timing
GROUP BY year, exploit_timing_category
ORDER BY year, exploit_timing_category;
```

* **Superset Chart Type**: Stacked Bar Chart  
* **Superset Configuration**:  
  * **X-axis**: year  
  * **Y-axis**: cve_count  
  * **Stack By**: exploit_timing_category  
  * **Time Range**: Custom, e.g., 1999-01-01 to 2025-05-13

### **Ch5_Fig_5.3_CVE exploitation race pattern (1999-2025)**

* **Question Answered**: What is the overall trend in the "race" between CVE disclosure and exploit publication?  
* **SQL Query**: (This query calculates percentages for a stacked percentage line chart.)  
```sql
WITH exploit_timing_percentages AS (
    SELECT 
        STRFTIME(cm.date_reserved, '%Y') AS year,
        CASE 
            WHEN e.date_published < cm.date_reserved THEN 'Pre-CVE Exploit'
            WHEN DATE_DIFF('day', cm.date_reserved, e.date_published) = 0 THEN 'Zero-Day Exploit'
            WHEN e.date_published > cm.date_reserved THEN 'Post-CVE Exploit'
            ELSE 'Unknown'
        END AS exploit_timing_category,
        COUNT(DISTINCT cm.cve_id) AS cve_count
    FROM cve_main cm
    JOIN exploits e ON cm.cve_id = e.cve_id
    WHERE cm.state = 'PUBLISHED'
        AND cm.date_reserved >= '1999-01-01'
        AND cm.date_reserved <= '2025-05-13'
        AND e.date_published <= '2025-05-13'
        AND cm.date_reserved IS NOT NULL
        AND e.date_published IS NOT NULL
    GROUP BY year, exploit_timing_category
),
yearly_totals AS (
    SELECT 
        year,
        SUM(cve_count) AS total_cves_per_year
    FROM exploit_timing_percentages
    GROUP BY year
)
SELECT 
    etp.year,
    etp.exploit_timing_category,
    etp.cve_count,
    ROUND(etp.cve_count * 100.0 / yt.total_cves_per_year, 2) AS percentage
FROM exploit_timing_percentages etp
JOIN yearly_totals yt ON etp.year = yt.year
ORDER BY etp.year, percentage DESC;
```

* **Superset Chart Type**: Stacked Percentage Line Chart  
* **Superset Configuration**:  
  * **X-axis**: year  
  * **Y-axis**: percentage  
  * **Stack By**: exploit_timing_category  
  * **Time Range**: Custom, e.g., 1999-01-01 to 2025-05-13  
  * **Chart Options**: Set Y-axis to percentage format.

### **Ch5_Fig_5.4_Distribution of Microsoft-specific exploit timing relative to CVE reservation (1999-2025)**

* **Question Answered**: How has the timing of exploit publication for Microsoft vulnerabilities evolved relative to their disclosure?  
* **SQL Query**:  
```sql
WITH microsoft_cves AS (
    SELECT DISTINCT cm.cve_id
    FROM cve_main cm
    CROSS JOIN UNNEST(STRING_SPLIT(cm.cpes, ',')) AS cpe_unnest(cpe_entry)
    WHERE LOWER(SPLIT_PART(cpe_entry, ':', 4)) = 'microsoft'
        AND cm.state = 'PUBLISHED'
        AND cm.date_reserved >= '1999-01-01'
        AND cm.date_reserved <= '2025-05-13'
),
microsoft_exploit_timing AS (
    SELECT 
        cm.cve_id,
        cm.date_reserved,
        e.date_published as exploit_date,
        STRFTIME(cm.date_reserved, '%Y') AS year,
        CASE 
            WHEN e.date_published < cm.date_reserved THEN 'Pre-CVE Exploit'
            WHEN DATE_DIFF('day', cm.date_reserved, e.date_published) = 0 THEN 'Zero-Day Exploit'
            WHEN e.date_published > cm.date_reserved THEN 'Post-CVE Exploit'
            ELSE 'Unknown'
        END AS exploit_timing_category
    FROM cve_main cm
    JOIN exploits e ON cm.cve_id = e.cve_id
    WHERE cm.cve_id IN (SELECT cve_id FROM microsoft_cves)
        AND cm.date_reserved IS NOT NULL
        AND e.date_published IS NOT NULL
        AND e.date_published <= '2025-05-13'
)
SELECT 
    year,
    exploit_timing_category,
    COUNT(DISTINCT cve_id) AS cve_count
FROM microsoft_exploit_timing
GROUP BY year, exploit_timing_category
ORDER BY year, exploit_timing_category;
```

* **Superset Chart Type**: Stacked Bar Chart  
* **Superset Configuration**:  
  * **X-axis**: year  
  * **Y-axis**: cve_count  
  * **Stack By**: exploit_timing_category  
  * **Time Range**: Custom, e.g., 1999-01-01 to 2025-05-13

### **Ch5_Fig_5.5_Microsoft Patched Vulnerabilities by Year (2016-2025)**

* **Question Answered**: How has the volume of patches released by Microsoft changed annually?  
* **SQL Query**:  
```sql
SELECT 
    STRFTIME(initial_release_date, '%Y') AS year,
    COUNT(DISTINCT cve_id) AS patched_cve_count
FROM msrc_patches 
WHERE initial_release_date >= '2016-01-01' 
    AND initial_release_date <= '2025-05-13'
    AND initial_release_date IS NOT NULL
GROUP BY year
ORDER BY year;
```

* **Superset Chart Type**: Bar Chart  
* **Superset Configuration**:  
  * **X-axis**: year  
  * **Y-axis**: patched_cve_count  
  * **Time Range**: Custom, 2016-01-01 to 2025-05-13

### **Ch5_Fig_5.5_Multi_Vendor_Patched Vulnerabilities by Year (2016-2025)**

* **Question Answered**: How has the volume of patches released by all vendors changed annually?
* **SQL Query**: 
```sql
WITH unified_patches AS (
    SELECT 
        cve_id,
        initial_release_date as patch_date,
        'Microsoft' AS vendor
    FROM msrc_patches 
    WHERE initial_release_date >= '2016-01-01' 
        AND initial_release_date <= '2025-05-13'
        AND initial_release_date IS NOT NULL
    
    UNION ALL
    
    SELECT 
        cve_id,
        initial_release_date as patch_date,
        'RedHat' AS vendor
    FROM redhat_patches 
    WHERE initial_release_date >= '2016-01-01'
        AND initial_release_date <= '2025-05-13'
        AND initial_release_date IS NOT NULL
        AND (LOWER(product_name) LIKE '%rhel%' OR LOWER(product_name) LIKE '%red hat%' OR LOWER(product_name) LIKE '%enterprise linux%')
    
    UNION ALL
    
    SELECT 
        cve_id,
        initial_release_date as patch_date,
        'Cisco' AS vendor
    FROM cisco_patches 
    WHERE initial_release_date >= '2016-01-01'
        AND initial_release_date <= '2025-05-13'
        AND initial_release_date IS NOT NULL
)
SELECT 
    STRFTIME(patch_date, '%Y') AS year,
    vendor,
    COUNT(DISTINCT cve_id) AS patched_cve_count
FROM unified_patches
GROUP BY year, vendor
ORDER BY year, vendor;
```

### **Ch5_Fig_5.6_Time to Patch by Vulnerability Severity**

* **Question Answered**: How does the time it takes to release a patch vary by the vulnerability's severity?  
* **SQL Query**: (This query uses msrc_patches for Microsoft-specific data as per the original figure. You could adapt it to use unified_patches for an overall view.)  
```sql
WITH microsoft_patch_timing AS (
    SELECT 
        cm.cve_id,
        cm.date_reserved,
        mp.initial_release_date,
        cm.cvss_v3_severity,
        DATE_DIFF('day', cm.date_reserved, mp.initial_release_date) AS days_to_patch
    FROM cve_main cm
    JOIN msrc_patches mp ON cm.cve_id = mp.cve_id
    WHERE cm.cvss_v3_severity IS NOT NULL 
        AND cm.cvss_v3_severity IN ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW')
        AND cm.date_reserved IS NOT NULL
        AND mp.initial_release_date IS NOT NULL
        AND mp.initial_release_date >= '2016-01-01'
        AND mp.initial_release_date <= '2025-05-13'
        AND cm.state = 'PUBLISHED'
)
SELECT 
    cvss_v3_severity AS severity_level,
    MEDIAN(days_to_patch) AS median_days_to_patch,
    AVG(days_to_patch) AS avg_days_to_patch,
    COUNT(cve_id) AS sample_size
FROM microsoft_patch_timing
WHERE days_to_patch >= 0  -- Filter out negative values (patch before CVE reserved)
GROUP BY cvss_v3_severity
ORDER BY 
    CASE cvss_v3_severity 
        WHEN 'CRITICAL' THEN 1 
        WHEN 'HIGH' THEN 2 
        WHEN 'MEDIUM' THEN 3 
        WHEN 'LOW' THEN 4 
    END;
```

* **Superset Chart Type**: Bar Chart  
* **Superset Configuration**:  
  * **X-axis**: severity_level  
  * **Y-axis**: median_days_to_patch  
  * **Sort By**: Custom order (Critical, High, Medium, Low)

### **Ch5_Fig_5.6_Multi-vendor Time to Patch by Vulnerability Severity**

* **Question Answered**: How does the time it takes to release a patch vary by the vulnerability's severity?  
* **SQL Query**: (This query for all vendors)  

```sql
WITH unified_patch_timing AS (
    -- Microsoft
    SELECT 
        cm.cve_id,
        cm.date_reserved,
        mp.initial_release_date as patch_date,
        cm.cvss_v3_severity,
        'Microsoft' as vendor,
        DATE_DIFF('day', cm.date_reserved, mp.initial_release_date) AS days_to_patch
    FROM cve_main cm
    JOIN msrc_patches mp ON cm.cve_id = mp.cve_id
    WHERE cm.cvss_v3_severity IN ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW')
        AND cm.date_reserved IS NOT NULL
        AND mp.initial_release_date >= '2016-01-01'
        AND mp.initial_release_date <= '2025-05-13'
        AND cm.state = 'PUBLISHED'
    
    UNION ALL
    
    -- RedHat
    SELECT 
        cm.cve_id,
        cm.date_reserved,
        rp.initial_release_date as patch_date,
        cm.cvss_v3_severity,
        'RedHat' as vendor,
        DATE_DIFF('day', cm.date_reserved, rp.initial_release_date) AS days_to_patch
    FROM cve_main cm
    JOIN redhat_patches rp ON cm.cve_id = rp.cve_id
    WHERE cm.cvss_v3_severity IN ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW')
        AND cm.date_reserved IS NOT NULL
        AND rp.initial_release_date >= '2016-01-01'
        AND rp.initial_release_date <= '2025-05-13'
        AND cm.state = 'PUBLISHED'
        AND (LOWER(rp.product_name) LIKE '%rhel%' OR LOWER(rp.product_name) LIKE '%red hat%' OR LOWER(rp.product_name) LIKE '%enterprise linux%')
    
    UNION ALL
    
    -- Cisco
    SELECT 
        cm.cve_id,
        cm.date_reserved,
        cp.initial_release_date as patch_date,
        cm.cvss_v3_severity,
        'Cisco' as vendor,
        DATE_DIFF('day', cm.date_reserved, cp.initial_release_date) AS days_to_patch
    FROM cve_main cm
    JOIN cisco_patches cp ON cm.cve_id = cp.cve_id
    WHERE cm.cvss_v3_severity IN ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW')
        AND cm.date_reserved IS NOT NULL
        AND cp.initial_release_date >= '2016-01-01'
        AND cp.initial_release_date <= '2025-05-13'
        AND cm.state = 'PUBLISHED'
)
SELECT 
    cvss_v3_severity AS severity_level,
    vendor,
    MEDIAN(days_to_patch) AS median_days_to_patch,
    COUNT(cve_id) AS sample_size
FROM unified_patch_timing
WHERE days_to_patch >= 0
GROUP BY cvss_v3_severity, vendor
ORDER BY 
    CASE cvss_v3_severity 
        WHEN 'CRITICAL' THEN 1 
        WHEN 'HIGH' THEN 2 
        WHEN 'MEDIUM' THEN 3 
        WHEN 'LOW' THEN 4 
    END, vendor;
```

### **Ch5_Fig_5.7_Distribution of differences in days between Exploit Adding date and CVE Creation date for Microsoft products**

* **Question Answered**: What is the typical time gap between CVE disclosure and exploit publication for Microsoft products?  
* **SQL Query**:  
```sql
WITH microsoft_cves AS (
    -- Identify distinct CVEs related to Microsoft, applying initial filters.
    -- This CTE handles the unnesting robustly for DuckDB.
    SELECT DISTINCT cm.cve_id
    FROM cve_main cm
    , UNNEST(STRING_SPLIT(cm.cpes, ',')) AS cpe_entry(value)
    WHERE LOWER(SPLIT_PART(cpe_entry.value, ':', 4)) = 'microsoft'
        AND cm.state = 'PUBLISHED'
        AND cm.date_reserved IS NOT NULL
        AND cm.date_reserved <= CURRENT_DATE
        AND cm.cpes IS NOT NULL
        AND cm.cpes != ''
),
microsoft_exploit_gaps AS (
    -- Calculate the days_to_exploit for identified Microsoft CVEs with exploits.
    SELECT
        cm.cve_id,
        cm.date_reserved,
        e.date_published AS exploit_date,
        DATE_DIFF('day', cm.date_reserved, e.date_published) AS days_to_exploit
    FROM cve_main cm
    JOIN exploits e ON cm.cve_id = e.cve_id
    WHERE cm.cve_id IN (SELECT cve_id FROM microsoft_cves)
        AND e.date_published IS NOT NULL
        AND e.date_published <= CURRENT_DATE
),
-- Assign categories to each exploit gap record for easier grouping
categorized_gaps_with_mode_input AS (
    SELECT
        cve_id,
        days_to_exploit,
        CASE
            WHEN days_to_exploit < -365 THEN '< -365 days (More than 1 year before CVE)'
            WHEN days_to_exploit BETWEEN -365 AND -181 THEN '-365 to -181 days (6 months to 1 year before CVE)'
            WHEN days_to_exploit BETWEEN -180 AND -91 THEN '-180 to -91 days (3 to 6 months before CVE)'
            WHEN days_to_exploit BETWEEN -90 AND -31 THEN '-90 to -31 days (1 to 3 months before CVE)'
            WHEN days_to_exploit BETWEEN -30 AND -1 THEN '-30 to -1 days (Up to 1 month before CVE)'
            WHEN days_to_exploit = 0 THEN '0 days (Same day as CVE)'
            WHEN days_to_exploit BETWEEN 1 AND 30 THEN '1 to 30 days (Up to 1 month after CVE)'
            WHEN days_to_exploit BETWEEN 31 AND 90 THEN '31 to 90 days (1 to 3 months after CVE)'
            WHEN days_to_exploit BETWEEN 91 AND 180 THEN '91 to 180 days (3 to 6 months after CVE)'
            WHEN days_to_exploit BETWEEN 181 AND 365 THEN '181 to 365 days (6 months to 1 year after CVE)'
            WHEN days_to_exploit > 365 THEN '> 365 days (More than 1 year after CVE)'
            ELSE 'Unknown'
        END AS time_gap_category
    FROM microsoft_exploit_gaps
),
-- Calculate statistics for each category (count, avg, median, mode)
categorized_stats AS (
    SELECT
        time_gap_category,
        COUNT(cve_id) AS cve_count,
        CAST(AVG(days_to_exploit) AS DECIMAL(10, 2)) AS avg_days_to_exploit,
        CAST(MEDIAN(days_to_exploit) AS DECIMAL(10, 2)) AS median_days_to_exploit,
        -- Subquery to calculate mode for the current category
        (
            SELECT days_to_exploit
            FROM categorized_gaps_with_mode_input AS sub
            WHERE sub.time_gap_category = categorized_gaps_with_mode_input.time_gap_category
            GROUP BY days_to_exploit
            ORDER BY COUNT(*) DESC, days_to_exploit ASC -- Order by value for consistent tie-breaking
            LIMIT 1
        ) AS mode_days_to_exploit
    FROM categorized_gaps_with_mode_input
    GROUP BY time_gap_category
),
-- Calculate overall statistics (count, avg, median, mode)
overall_stats AS (
    SELECT
        'Overall Distribution' AS time_gap_category,
        COUNT(cve_id) AS cve_count,
        CAST(AVG(days_to_exploit) AS DECIMAL(10, 2)) AS avg_days_to_exploit,
        CAST(MEDIAN(days_to_exploit) AS DECIMAL(10, 2)) AS median_days_to_exploit,
        -- Subquery to calculate overall mode
        (
            SELECT days_to_exploit
            FROM microsoft_exploit_gaps
            GROUP BY days_to_exploit
            ORDER BY COUNT(*) DESC, days_to_exploit ASC -- Order by value for consistent tie-breaking
            LIMIT 1
        ) AS mode_days_to_exploit
    FROM microsoft_exploit_gaps
)
-- Wrap the UNION ALL in a subquery (derived table) and then apply ORDER BY
SELECT *
FROM (
    SELECT * FROM categorized_stats
    UNION ALL
    SELECT * FROM overall_stats
) AS combined_results
ORDER BY
    CASE
        WHEN time_gap_category = '< -365 days (More than 1 year before CVE)' THEN 1
        WHEN time_gap_category = '-365 to -181 days (6 months to 1 year before CVE)' THEN 2
        WHEN time_gap_category = '-180 to -91 days (3 to 6 months before CVE)' THEN 3
        WHEN time_gap_category = '-90 to -31 days (1 to 3 months before CVE)' THEN 4
        WHEN time_gap_category = '-30 to -1 days (Up to 1 month before CVE)' THEN 5
        WHEN time_gap_category = '0 days (Same day as CVE)' THEN 6
        WHEN time_gap_category = '1 to 30 days (Up to 1 month after CVE)' THEN 7
        WHEN time_gap_category = '31 to 90 days (1 to 3 months after CVE)' THEN 8
        WHEN time_gap_category = '91 to 180 days (3 to 6 months after CVE)' THEN 9
        WHEN time_gap_category = '181 to 365 days (6 months to 1 year after CVE)' THEN 10
        WHEN time_gap_category = '> 365 days (More than 1 year after CVE)' THEN 11
        WHEN time_gap_category = 'Overall Distribution' THEN 100 -- Ensures overall row appears last
        ELSE 12
    END;
```

* **Superset Chart Type**: Histogram  
* **Superset Configuration**:  
  * **Metric**: days_to_exploit  
  * **Binning**: Adjust bin size as needed (e.g., 30 days)

### **Ch5_Fig_5.7.1_Distribution of differences in days between Exploit Adding date and CVE Creation date (All CVEs with patch and exploit)**

```sql
WITH all_cves_with_patch_and_exploit AS (
    SELECT DISTINCT cm.cve_id
    FROM cve_main cm
    WHERE cm.state = 'PUBLISHED'
        AND cm.date_reserved IS NOT NULL
        AND cm.date_reserved <= CURRENT_DATE
        AND EXISTS (
            SELECT 1 FROM msrc_patches mp
            WHERE mp.cve_id = cm.cve_id AND mp.initial_release_date IS NOT NULL AND mp.initial_release_date <= CURRENT_DATE
            UNION ALL
            SELECT 1 FROM redhat_patches rp
            WHERE rp.cve_id = cm.cve_id AND rp.initial_release_date IS NOT NULL AND rp.initial_release_date <= CURRENT_DATE
                AND (LOWER(rp.product_name) LIKE '%rhel%' OR LOWER(rp.product_name) LIKE '%red hat%' OR LOWER(rp.product_name) LIKE '%enterprise linux%')
            UNION ALL
            SELECT 1 FROM cisco_patches cp
            WHERE cp.cve_id = cm.cve_id AND cp.initial_release_date IS NOT NULL AND cp.initial_release_date <= CURRENT_DATE
        )
        AND EXISTS (
            SELECT 1 FROM exploits e
            WHERE e.cve_id = cm.cve_id AND e.date_published IS NOT NULL AND e.date_published <= CURRENT_DATE
        )
),
all_exploit_gaps AS (
    SELECT
        cm.cve_id,
        cm.date_reserved,
        e.date_published AS exploit_date,
        DATE_DIFF('day', cm.date_reserved, e.date_published) AS days_to_exploit
    FROM cve_main cm
    JOIN exploits e ON cm.cve_id = e.cve_id
    WHERE cm.cve_id IN (SELECT cve_id FROM all_cves_with_patch_and_exploit)
),
-- Assign the 12 categories to each exploit gap record for grouping and mode calculation
categorized_gaps_with_mode_input AS (
    SELECT
        cve_id,
        days_to_exploit,
        CASE
            WHEN days_to_exploit < -365 THEN '< -365 days (More than 1 year before CVE)'
            WHEN days_to_exploit BETWEEN -365 AND -181 THEN '-365 to -181 days (6 months to 1 year before CVE)'
            WHEN days_to_exploit BETWEEN -180 AND -91 THEN '-180 to -91 days (3 to 6 months before CVE)'
            WHEN days_to_exploit BETWEEN -90 AND -31 THEN '-90 to -31 days (1 to 3 months before CVE)'
            WHEN days_to_exploit BETWEEN -30 AND -1 THEN '-30 to -1 days (Up to 1 month before CVE)'
            WHEN days_to_exploit = 0 THEN '0 days (Same day as CVE)'
            WHEN days_to_exploit BETWEEN 1 AND 30 THEN '1 to 30 days (Up to 1 month after CVE)'
            WHEN days_to_exploit BETWEEN 31 AND 90 THEN '31 to 90 days (1 to 3 months after CVE)'
            WHEN days_to_exploit BETWEEN 91 AND 180 THEN '91 to 180 days (3 to 6 months after CVE)'
            WHEN days_to_exploit BETWEEN 181 AND 365 THEN '181 to 365 days (6 months to 1 year after CVE)'
            WHEN days_to_exploit > 365 THEN '> 365 days (More than 1 year after CVE)'
            ELSE 'Unknown'
        END AS time_gap_category
    FROM all_exploit_gaps
),
-- Calculate statistics for each category (count, avg, median, mode)
categorized_stats AS (
    SELECT
        time_gap_category,
        COUNT(cve_id) AS cve_count,
        CAST(AVG(days_to_exploit) AS DECIMAL(10, 2)) AS avg_days_to_exploit,
        CAST(MEDIAN(days_to_exploit) AS DECIMAL(10, 2)) AS median_days_to_exploit,
        -- Subquery to calculate mode for the current category
        (
            SELECT days_to_exploit
            FROM categorized_gaps_with_mode_input AS sub
            WHERE sub.time_gap_category = categorized_gaps_with_mode_input.time_gap_category
            GROUP BY days_to_exploit
            ORDER BY COUNT(*) DESC, days_to_exploit ASC
            LIMIT 1
        ) AS mode_days_to_exploit
    FROM categorized_gaps_with_mode_input
    GROUP BY time_gap_category
),
-- Calculate overall statistics (count, avg, median, mode)
overall_stats AS (
    SELECT
        'Overall Distribution' AS time_gap_category,
        COUNT(cve_id) AS cve_count,
        CAST(AVG(days_to_exploit) AS DECIMAL(10, 2)) AS avg_days_to_exploit,
        CAST(MEDIAN(days_to_exploit) AS DECIMAL(10, 2)) AS median_days_to_exploit,
        -- Subquery to calculate overall mode
        (
            SELECT days_to_exploit
            FROM all_exploit_gaps
            GROUP BY days_to_exploit
            ORDER BY COUNT(*) DESC, days_to_exploit ASC
            LIMIT 1
        ) AS mode_days_to_exploit
    FROM all_exploit_gaps
)
-- Wrap the UNION ALL in a subquery (derived table) and then apply ORDER BY
SELECT *
FROM (
    SELECT * FROM categorized_stats
    UNION ALL
    SELECT * FROM overall_stats
) AS combined_results
ORDER BY
    CASE
        WHEN time_gap_category = '< -365 days (More than 1 year before CVE)' THEN 1
        WHEN time_gap_category = '-365 to -181 days (6 months to 1 year before CVE)' THEN 2
        WHEN time_gap_category = '-180 to -91 days (3 to 6 months before CVE)' THEN 3
        WHEN time_gap_category = '-90 to -31 days (1 to 3 months before CVE)' THEN 4
        WHEN time_gap_category = '-30 to -1 days (Up to 1 month before CVE)' THEN 5
        WHEN time_gap_category = '0 days (Same day as CVE)' THEN 6
        WHEN time_gap_category = '1 to 30 days (Up to 1 month after CVE)' THEN 7
        WHEN time_gap_category = '31 to 90 days (1 to 3 months after CVE)' THEN 8
        WHEN time_gap_category = '91 to 180 days (3 to 6 months after CVE)' THEN 9
        WHEN time_gap_category = '181 to 365 days (6 months to 1 year after CVE)' THEN 10
        WHEN time_gap_category = '> 365 days (More than 1 year after CVE)' THEN 11
        WHEN time_gap_category = 'Unknown' THEN 12
        WHEN time_gap_category = 'Overall Distribution' THEN 100 -- Ensures overall row appears last
        ELSE 101 -- Fallback for any unexpected categories
    END;
```
### **Ch5_Fig_5.7.2_Distribution of differences in days between CVE Creation date and Patch date for Microsoft products**

```sql
WITH microsoft_cves_with_patch_and_exploit AS (
    SELECT DISTINCT cm.cve_id
    FROM cve_main cm
    CROSS JOIN UNNEST(STRING_SPLIT(cm.cpes, ',')) AS cpe_unnest(cpe_entry)
    JOIN msrc_patches mp ON cm.cve_id = mp.cve_id
    JOIN exploits e ON cm.cve_id = e.cve_id
    WHERE LOWER(SPLIT_PART(cpe_entry, ':', 4)) = 'microsoft'
        AND cm.state = 'PUBLISHED'
        AND cm.date_reserved IS NOT NULL
        AND mp.initial_release_date IS NOT NULL
        AND e.date_published IS NOT NULL
        AND mp.initial_release_date <= CURRENT_DATE
        AND e.date_published <= CURRENT_DATE
),
microsoft_patch_gaps AS (
    SELECT
        cm.cve_id,
        cm.date_reserved,
        mp.initial_release_date AS patch_date,
        DATE_DIFF('day', cm.date_reserved, mp.initial_release_date) AS days_to_patch
    FROM cve_main cm
    JOIN msrc_patches mp ON cm.cve_id = mp.cve_id
    WHERE cm.cve_id IN (SELECT cve_id FROM microsoft_cves_with_patch_and_exploit)
),
-- Assign the 12 categories to each patch gap record for grouping and mode calculation
categorized_gaps_with_mode_input AS (
    SELECT
        cve_id,
        days_to_patch,
        CASE
            WHEN days_to_patch < -365 THEN '< -365 days (More than 1 year before CVE)'
            WHEN days_to_patch BETWEEN -365 AND -181 THEN '-365 to -181 days (6 months to 1 year before CVE)'
            WHEN days_to_patch BETWEEN -180 AND -91 THEN '-180 to -91 days (3 to 6 months before CVE)'
            WHEN days_to_patch BETWEEN -90 AND -31 THEN '-90 to -31 days (1 to 3 months before CVE)'
            WHEN days_to_patch BETWEEN -30 AND -1 THEN '-30 to -1 days (Up to 1 month before CVE)'
            WHEN days_to_patch = 0 THEN '0 days (Same day as CVE)'
            WHEN days_to_patch BETWEEN 1 AND 30 THEN '1 to 30 days (Up to 1 month after CVE)'
            WHEN days_to_patch BETWEEN 31 AND 90 THEN '31 to 90 days (1 to 3 months after CVE)'
            WHEN days_to_patch BETWEEN 91 AND 180 THEN '91 to 180 days (3 to 6 months after CVE)'
            WHEN days_to_patch BETWEEN 181 AND 365 THEN '181 to 365 days (6 months to 1 year after CVE)'
            WHEN days_to_patch > 365 THEN '> 365 days (More than 1 year after CVE)'
            ELSE 'Unknown'
        END AS time_gap_category
    FROM microsoft_patch_gaps
),
-- Calculate statistics for each category (count, avg, median, mode)
categorized_stats AS (
    SELECT
        time_gap_category,
        COUNT(cve_id) AS cve_count,
        CAST(AVG(days_to_patch) AS DECIMAL(10, 2)) AS avg_days_to_patch,
        CAST(MEDIAN(days_to_patch) AS DECIMAL(10, 2)) AS median_days_to_patch,
        -- Subquery to calculate mode for the current category
        (
            SELECT days_to_patch
            FROM categorized_gaps_with_mode_input AS sub
            WHERE sub.time_gap_category = categorized_gaps_with_mode_input.time_gap_category
            GROUP BY days_to_patch
            ORDER BY COUNT(*) DESC, days_to_patch ASC
            LIMIT 1
        ) AS mode_days_to_patch
    FROM categorized_gaps_with_mode_input
    GROUP BY time_gap_category
),
-- Calculate overall statistics (count, avg, median, mode)
overall_stats AS (
    SELECT
        'Overall Distribution' AS time_gap_category,
        COUNT(cve_id) AS cve_count,
        CAST(AVG(days_to_patch) AS DECIMAL(10, 2)) AS avg_days_to_patch,
        CAST(MEDIAN(days_to_patch) AS DECIMAL(10, 2)) AS median_days_to_patch,
        -- Subquery to calculate overall mode
        (
            SELECT days_to_patch
            FROM microsoft_patch_gaps
            GROUP BY days_to_patch
            ORDER BY COUNT(*) DESC, days_to_patch ASC
            LIMIT 1
        ) AS mode_days_to_patch
    FROM microsoft_patch_gaps
)
-- Wrap the UNION ALL in a subquery (derived table) and then apply ORDER BY
SELECT *
FROM (
    SELECT * FROM categorized_stats
    UNION ALL
    SELECT * FROM overall_stats
) AS combined_results
ORDER BY
    CASE
        WHEN time_gap_category = '< -365 days (More than 1 year before CVE)' THEN 1
        WHEN time_gap_category = '-365 to -181 days (6 months to 1 year before CVE)' THEN 2
        WHEN time_gap_category = '-180 to -91 days (3 to 6 months before CVE)' THEN 3
        WHEN time_gap_category = '-90 to -31 days (1 to 3 months before CVE)' THEN 4
        WHEN time_gap_category = '-30 to -1 days (Up to 1 month before CVE)' THEN 5
        WHEN time_gap_category = '0 days (Same day as CVE)' THEN 6
        WHEN time_gap_category = '1 to 30 days (Up to 1 month after CVE)' THEN 7
        WHEN time_gap_category = '31 to 90 days (1 to 3 months after CVE)' THEN 8
        WHEN time_gap_category = '91 to 180 days (3 to 6 months after CVE)' THEN 9
        WHEN time_gap_category = '181 to 365 days (6 months to 1 year after CVE)' THEN 10
        WHEN time_gap_category = '> 365 days (More than 1 year after CVE)' THEN 11
        WHEN time_gap_category = 'Unknown' THEN 12
        WHEN time_gap_category = 'Overall Distribution' THEN 100 -- Ensures overall row appears last
        ELSE 101 -- Fallback for any unexpected categories
    END;
```

### **Ch5_Fig_5.7.3_Distribution of differences in days between CVE Creation date and Patch date (All CVEs with patch and exploit)**

**Question Answered**: What is the typical time gap between CVE disclosure and patch release for all vendors (CVEs with both patch and exploit)?
```sql
WITH all_cves_with_patch_and_exploit AS (
    SELECT DISTINCT cm.cve_id
    FROM cve_main cm
    WHERE cm.state = 'PUBLISHED'
        AND cm.date_reserved IS NOT NULL
        AND cm.date_reserved <= CURRENT_DATE -- Updated date
        AND EXISTS (
            SELECT 1 FROM msrc_patches mp
            WHERE mp.cve_id = cm.cve_id AND mp.initial_release_date IS NOT NULL AND mp.initial_release_date <= CURRENT_DATE -- Updated date
            UNION ALL
            SELECT 1 FROM redhat_patches rp
            WHERE rp.cve_id = cm.cve_id AND rp.initial_release_date IS NOT NULL AND rp.initial_release_date <= CURRENT_DATE -- Updated date
                AND (LOWER(rp.product_name) LIKE '%rhel%' OR LOWER(rp.product_name) LIKE '%red hat%' OR LOWER(rp.product_name) LIKE '%enterprise linux%')
            UNION ALL
            SELECT 1 FROM cisco_patches cp
            WHERE cp.cve_id = cm.cve_id AND cp.initial_release_date IS NOT NULL AND cp.initial_release_date <= CURRENT_DATE -- Updated date
        )
        AND EXISTS (
            SELECT 1 FROM exploits e
            WHERE e.cve_id = cm.cve_id AND e.date_published IS NOT NULL AND e.date_published <= CURRENT_DATE -- Updated date
        )
),
unified_patch_gaps AS (
    -- Microsoft patches
    SELECT
        cm.cve_id,
        cm.date_reserved,
        mp.initial_release_date AS patch_date,
        'Microsoft' AS vendor,
        DATE_DIFF('day', cm.date_reserved, mp.initial_release_date) AS days_to_patch
    FROM cve_main cm
    JOIN msrc_patches mp ON cm.cve_id = mp.cve_id
    WHERE cm.cve_id IN (SELECT cve_id FROM all_cves_with_patch_and_exploit)

    UNION ALL

    -- RedHat patches
    SELECT
        cm.cve_id,
        cm.date_reserved,
        rp.initial_release_date AS patch_date,
        'RedHat' AS vendor,
        DATE_DIFF('day', cm.date_reserved, rp.initial_release_date) AS days_to_patch
    FROM cve_main cm
    JOIN redhat_patches rp ON cm.cve_id = rp.cve_id
    WHERE cm.cve_id IN (SELECT cve_id FROM all_cves_with_patch_and_exploit)
        AND (LOWER(rp.product_name) LIKE '%rhel%' OR LOWER(rp.product_name) LIKE '%red hat%' OR LOWER(rp.product_name) LIKE '%enterprise linux%')

    UNION ALL

    -- Cisco patches
    SELECT
        cm.cve_id,
        cm.date_reserved,
        cp.initial_release_date AS patch_date,
        'Cisco' AS vendor,
        DATE_DIFF('day', cm.date_reserved, cp.initial_release_date) AS days_to_patch
    FROM cve_main cm
    JOIN cisco_patches cp ON cm.cve_id = cp.cve_id
    WHERE cm.cve_id IN (SELECT cve_id FROM all_cves_with_patch_and_exploit)
),
-- Assign the 12 categories to each patch gap record for grouping and mode calculation
categorized_gaps_with_mode_input AS (
    SELECT
        cve_id,
        days_to_patch,
        CASE
            WHEN days_to_patch < -365 THEN '< -365 days (More than 1 year before CVE)'
            WHEN days_to_patch BETWEEN -365 AND -181 THEN '-365 to -181 days (6 months to 1 year before CVE)'
            WHEN days_to_patch BETWEEN -180 AND -91 THEN '-180 to -91 days (3 to 6 months before CVE)'
            WHEN days_to_patch BETWEEN -90 AND -31 THEN '-90 to -31 days (1 to 3 months before CVE)'
            WHEN days_to_patch BETWEEN -30 AND -1 THEN '-30 to -1 days (Up to 1 month before CVE)'
            WHEN days_to_patch = 0 THEN '0 days (Same day as CVE)'
            WHEN days_to_patch BETWEEN 1 AND 30 THEN '1 to 30 days (Up to 1 month after CVE)'
            WHEN days_to_patch BETWEEN 31 AND 90 THEN '31 to 90 days (1 to 3 months after CVE)'
            WHEN days_to_patch BETWEEN 91 AND 180 THEN '91 to 180 days (3 to 6 months after CVE)'
            WHEN days_to_patch BETWEEN 181 AND 365 THEN '181 to 365 days (6 months to 1 year after CVE)'
            WHEN days_to_patch > 365 THEN '> 365 days (More than 1 year after CVE)'
            ELSE 'Unknown'
        END AS time_gap_category
    FROM unified_patch_gaps
),
-- Calculate statistics for each category (count, avg, median, mode)
categorized_stats AS (
    SELECT
        time_gap_category,
        COUNT(cve_id) AS cve_count,
        CAST(AVG(days_to_patch) AS DECIMAL(10, 2)) AS avg_days_to_patch,
        CAST(MEDIAN(days_to_patch) AS DECIMAL(10, 2)) AS median_days_to_patch,
        -- Subquery to calculate mode for the current category
        (
            SELECT days_to_patch
            FROM categorized_gaps_with_mode_input AS sub
            WHERE sub.time_gap_category = categorized_gaps_with_mode_input.time_gap_category
            GROUP BY days_to_patch
            ORDER BY COUNT(*) DESC, days_to_patch ASC
            LIMIT 1
        ) AS mode_days_to_patch
    FROM categorized_gaps_with_mode_input
    GROUP BY time_gap_category
),
-- Calculate overall statistics (count, avg, median, mode)
overall_stats AS (
    SELECT
        'Overall Distribution' AS time_gap_category,
        COUNT(cve_id) AS cve_count,
        CAST(AVG(days_to_patch) AS DECIMAL(10, 2)) AS avg_days_to_patch,
        CAST(MEDIAN(days_to_patch) AS DECIMAL(10, 2)) AS median_days_to_patch,
        -- Subquery to calculate overall mode
        (
            SELECT days_to_patch
            FROM unified_patch_gaps
            GROUP BY days_to_patch
            ORDER BY COUNT(*) DESC, days_to_patch ASC
            LIMIT 1
        ) AS mode_days_to_patch
    FROM unified_patch_gaps
)
-- Wrap the UNION ALL in a subquery (derived table) and then apply ORDER BY
SELECT *
FROM (
    SELECT * FROM categorized_stats
    UNION ALL
    SELECT * FROM overall_stats
) AS combined_results
ORDER BY
    CASE
        WHEN time_gap_category = '< -365 days (More than 1 year before CVE)' THEN 1
        WHEN time_gap_category = '-365 to -181 days (6 months to 1 year before CVE)' THEN 2
        WHEN time_gap_category = '-180 to -91 days (3 to 6 months before CVE)' THEN 3
        WHEN time_gap_category = '-90 to -31 days (1 to 3 months before CVE)' THEN 4
        WHEN time_gap_category = '-30 to -1 days (Up to 1 month before CVE)' THEN 5
        WHEN time_gap_category = '0 days (Same day as CVE)' THEN 6
        WHEN time_gap_category = '1 to 30 days (Up to 1 month after CVE)' THEN 7
        WHEN time_gap_category = '31 to 90 days (1 to 3 months after CVE)' THEN 8
        WHEN time_gap_category = '91 to 180 days (3 to 6 months after CVE)' THEN 9
        WHEN time_gap_category = '181 to 365 days (6 months to 1 year after CVE)' THEN 10
        WHEN time_gap_category = '> 365 days (More than 1 year after CVE)' THEN 11
        WHEN time_gap_category = 'Unknown' THEN 12
        WHEN time_gap_category = 'Overall Distribution' THEN 100 -- Ensures overall row appears last
        ELSE 101 -- Fallback for any unexpected categories
    END;
```

### **fig:lifecycle_exp_minus_creation: Distribution of differences in days between Exploit Adding date and CVE Creation date (including third-party applications)**

* **Question Answered**: How does the time gap between CVE disclosure and exploit publication change when including third-party apps in the Microsoft ecosystem?  
* **SQL Query**:  
  SELECT  
      DATEDIFF('day', cm.date_reserved, e.date_published) AS days_to_exploit  
  FROM  
      cve_main AS cm  
  JOIN  
      exploits AS e ON cm.cve_id = e.cve_id  
  WHERE  
      cm.date_reserved IS NOT NULL  
      AND e.date_published IS NOT NULL  
      AND e.date_published <= '2025-05-13';

* **Superset Chart Type**: Histogram  
* **Superset Configuration**:  
  * **Metric**: days_to_exploit  
  * **Binning**: Adjust bin size as needed (e.g., 30 days)

### **Ch5_Fig_5.9_Distribution of differences in days between Patch Availability and Exploit Adding dates for Microsoft products**

* **Question Answered**: What is the typical time gap between exploit publication and patch availability for Microsoft products?  
* **SQL Query**:  
```sql
WITH microsoft_cves_with_patch_and_exploit AS (
    SELECT DISTINCT cm.cve_id
    FROM cve_main cm
    CROSS JOIN UNNEST(STRING_SPLIT(cm.cpes, ',')) AS cpe_unnest(cpe_entry)
    JOIN msrc_patches mp ON cm.cve_id = mp.cve_id
    JOIN exploits e ON cm.cve_id = e.cve_id
    WHERE LOWER(SPLIT_PART(cpe_entry, ':', 4)) = 'microsoft'
        AND cm.state = 'PUBLISHED'
        AND cm.date_reserved IS NOT NULL
        AND mp.initial_release_date IS NOT NULL
        AND e.date_published IS NOT NULL
        AND mp.initial_release_date <= CURRENT_DATE -- Updated date
        AND e.date_published <= CURRENT_DATE -- Updated date
),
microsoft_exploit_patch_gaps AS (
    SELECT
        cm.cve_id,
        e.date_published AS exploit_date,
        mp.initial_release_date AS patch_date,
        DATE_DIFF('day', e.date_published, mp.initial_release_date) AS patch_exploit_gap
    FROM cve_main cm
    JOIN exploits e ON cm.cve_id = e.cve_id
    JOIN msrc_patches mp ON cm.cve_id = mp.cve_id
    WHERE cm.cve_id IN (SELECT cve_id FROM microsoft_cves_with_patch_and_exploit)
),
-- Assign the 12 categories to each patch_exploit_gap record for grouping and mode calculation
categorized_gaps_with_mode_input AS (
    SELECT
        cve_id,
        patch_exploit_gap,
        CASE
            WHEN patch_exploit_gap < -365 THEN '< -365 days (More than 1 year before CVE)'
            WHEN patch_exploit_gap BETWEEN -365 AND -181 THEN '-365 to -181 days (6 months to 1 year before CVE)'
            WHEN patch_exploit_gap BETWEEN -180 AND -91 THEN '-180 to -91 days (3 to 6 months before CVE)'
            WHEN patch_exploit_gap BETWEEN -90 AND -31 THEN '-90 to -31 days (1 to 3 months before CVE)'
            WHEN patch_exploit_gap BETWEEN -30 AND -1 THEN '-30 to -1 days (Up to 1 month before CVE)'
            WHEN patch_exploit_gap = 0 THEN '0 days (Same day as CVE)'
            WHEN patch_exploit_gap BETWEEN 1 AND 30 THEN '1 to 30 days (Up to 1 month after CVE)'
            WHEN patch_exploit_gap BETWEEN 31 AND 90 THEN '31 to 90 days (1 to 3 months after CVE)'
            WHEN patch_exploit_gap BETWEEN 91 AND 180 THEN '91 to 180 days (3 to 6 months after CVE)'
            WHEN patch_exploit_gap BETWEEN 181 AND 365 THEN '181 to 365 days (6 months to 1 year after CVE)'
            WHEN patch_exploit_gap > 365 THEN '> 365 days (More than 1 year after CVE)'
            ELSE 'Unknown'
        END AS time_gap_category
    FROM microsoft_exploit_patch_gaps
),
-- Calculate statistics for each category (count, avg, median, mode)
categorized_stats AS (
    SELECT
        time_gap_category,
        COUNT(cve_id) AS cve_count,
        CAST(AVG(patch_exploit_gap) AS DECIMAL(10, 2)) AS avg_patch_exploit_gap,
        CAST(MEDIAN(patch_exploit_gap) AS DECIMAL(10, 2)) AS median_patch_exploit_gap,
        -- Subquery to calculate mode for the current category
        (
            SELECT patch_exploit_gap
            FROM categorized_gaps_with_mode_input AS sub
            WHERE sub.time_gap_category = categorized_gaps_with_mode_input.time_gap_category
            GROUP BY patch_exploit_gap
            ORDER BY COUNT(*) DESC, patch_exploit_gap ASC
            LIMIT 1
        ) AS mode_patch_exploit_gap
    FROM categorized_gaps_with_mode_input
    GROUP BY time_gap_category
),
-- Calculate overall statistics (count, avg, median, mode)
overall_stats AS (
    SELECT
        'Overall Distribution' AS time_gap_category,
        COUNT(cve_id) AS cve_count,
        CAST(AVG(patch_exploit_gap) AS DECIMAL(10, 2)) AS avg_patch_exploit_gap,
        CAST(MEDIAN(patch_exploit_gap) AS DECIMAL(10, 2)) AS median_patch_exploit_gap,
        -- Subquery to calculate overall mode
        (
            SELECT patch_exploit_gap
            FROM microsoft_exploit_patch_gaps
            GROUP BY patch_exploit_gap
            ORDER BY COUNT(*) DESC, patch_exploit_gap ASC
            LIMIT 1
        ) AS mode_patch_exploit_gap
    FROM microsoft_exploit_patch_gaps
)
-- Wrap the UNION ALL in a subquery (derived table) and then apply ORDER BY
SELECT *
FROM (
    SELECT * FROM categorized_stats
    UNION ALL
    SELECT * FROM overall_stats
) AS combined_results
ORDER BY
    CASE
        WHEN time_gap_category = '< -365 days (More than 1 year before CVE)' THEN 1
        WHEN time_gap_category = '-365 to -181 days (6 months to 1 year before CVE)' THEN 2
        WHEN time_gap_category = '-180 to -91 days (3 to 6 months before CVE)' THEN 3
        WHEN time_gap_category = '-90 to -31 days (1 to 3 months before CVE)' THEN 4
        WHEN time_gap_category = '-30 to -1 days (Up to 1 month before CVE)' THEN 5
        WHEN time_gap_category = '0 days (Same day as CVE)' THEN 6
        WHEN time_gap_category = '1 to 30 days (Up to 1 month after CVE)' THEN 7
        WHEN time_gap_category = '31 to 90 days (1 to 3 months after CVE)' THEN 8
        WHEN time_gap_category = '91 to 180 days (3 to 6 months after CVE)' THEN 9
        WHEN time_gap_category = '181 to 365 days (6 months to 1 year after CVE)' THEN 10
        WHEN time_gap_category = '> 365 days (More than 1 year after CVE)' THEN 11
        WHEN time_gap_category = 'Unknown' THEN 12
        WHEN time_gap_category = 'Overall Distribution' THEN 100 -- Ensures overall row appears last
        ELSE 101 -- Fallback for any unexpected categories
    END;
```

* **Superset Chart Type**: Histogram  
* **Superset Configuration**:  
  * **Metric**: patch_exploit_gap  
  * **Binning**: Adjust bin size as needed (e.g., 30 days)


### **Ch5_Fig_5.10_Distribution of differences in days between Patch Availability and Exploit Adding dates (All CVEs with patch and exploit)**

* **Question Answered**: How does the time gap between exploit and patch change when including third-party apps in the Microsoft ecosystem?  
* **SQL Query**: (This query uses the unified_patches CTE for a comprehensive view.)  
```sql
WITH all_cves_with_patch_and_exploit AS (
    SELECT DISTINCT cm.cve_id
    FROM cve_main cm
    WHERE cm.state = 'PUBLISHED'
        AND cm.date_reserved IS NOT NULL
        AND cm.date_reserved <= CURRENT_DATE -- Updated date
        AND EXISTS (
            SELECT 1 FROM msrc_patches mp
            WHERE mp.cve_id = cm.cve_id AND mp.initial_release_date IS NOT NULL AND mp.initial_release_date <= CURRENT_DATE -- Updated date
            UNION ALL
            SELECT 1 FROM redhat_patches rp
            WHERE rp.cve_id = cm.cve_id AND rp.initial_release_date IS NOT NULL AND rp.initial_release_date <= CURRENT_DATE -- Updated date
                AND (LOWER(rp.product_name) LIKE '%rhel%' OR LOWER(rp.product_name) LIKE '%red hat%' OR LOWER(rp.product_name) LIKE '%enterprise linux%')
            UNION ALL
            SELECT 1 FROM cisco_patches cp
            WHERE cp.cve_id = cm.cve_id AND cp.initial_release_date IS NOT NULL AND cp.initial_release_date <= CURRENT_DATE -- Updated date
        )
        AND EXISTS (
            SELECT 1 FROM exploits e
            WHERE e.cve_id = cm.cve_id AND e.date_published IS NOT NULL AND e.date_published <= CURRENT_DATE -- Updated date
        )
),
unified_exploit_patch_gaps AS (
    -- Microsoft
    SELECT
        cm.cve_id,
        e.date_published AS exploit_date,
        mp.initial_release_date AS patch_date,
        'Microsoft' AS vendor,
        DATE_DIFF('day', e.date_published, mp.initial_release_date) AS patch_exploit_gap
    FROM cve_main cm
    JOIN exploits e ON cm.cve_id = e.cve_id
    JOIN msrc_patches mp ON cm.cve_id = mp.cve_id
    WHERE cm.cve_id IN (SELECT cve_id FROM all_cves_with_patch_and_exploit)

    UNION ALL

    -- RedHat
    SELECT
        cm.cve_id,
        e.date_published AS exploit_date,
        rp.initial_release_date AS patch_date,
        'RedHat' AS vendor,
        DATE_DIFF('day', e.date_published, rp.initial_release_date) AS patch_exploit_gap
    FROM cve_main cm
    JOIN exploits e ON cm.cve_id = e.cve_id
    JOIN redhat_patches rp ON cm.cve_id = rp.cve_id
    WHERE cm.cve_id IN (SELECT cve_id FROM all_cves_with_patch_and_exploit)
        AND (LOWER(rp.product_name) LIKE '%rhel%' OR LOWER(rp.product_name) LIKE '%red hat%' OR LOWER(rp.product_name) LIKE '%enterprise linux%')

    UNION ALL

    -- Cisco
    SELECT
        cm.cve_id,
        e.date_published AS exploit_date,
        cp.initial_release_date AS patch_date,
        'Cisco' AS vendor,
        DATE_DIFF('day', e.date_published, cp.initial_release_date) AS patch_exploit_gap
    FROM cve_main cm
    JOIN exploits e ON cm.cve_id = e.cve_id
    JOIN cisco_patches cp ON cm.cve_id = cp.cve_id
    WHERE cm.cve_id IN (SELECT cve_id FROM all_cves_with_patch_and_exploit)
),
-- Assign the 12 categories to each patch_exploit_gap record for grouping and mode calculation
categorized_gaps_with_mode_input AS (
    SELECT
        cve_id,
        patch_exploit_gap,
        CASE
            WHEN patch_exploit_gap < -365 THEN '< -365 days (More than 1 year before CVE)'
            WHEN patch_exploit_gap BETWEEN -365 AND -181 THEN '-365 to -181 days (6 months to 1 year before CVE)'
            WHEN patch_exploit_gap BETWEEN -180 AND -91 THEN '-180 to -91 days (3 to 6 months before CVE)'
            WHEN patch_exploit_gap BETWEEN -90 AND -31 THEN '-90 to -31 days (1 to 3 months before CVE)'
            WHEN patch_exploit_gap BETWEEN -30 AND -1 THEN '-30 to -1 days (Up to 1 month before CVE)'
            WHEN patch_exploit_gap = 0 THEN '0 days (Same day as CVE)'
            WHEN patch_exploit_gap BETWEEN 1 AND 30 THEN '1 to 30 days (Up to 1 month after CVE)'
            WHEN patch_exploit_gap BETWEEN 31 AND 90 THEN '31 to 90 days (1 to 3 months after CVE)'
            WHEN patch_exploit_gap BETWEEN 91 AND 180 THEN '91 to 180 days (3 to 6 months after CVE)'
            WHEN patch_exploit_gap BETWEEN 181 AND 365 THEN '181 to 365 days (6 months to 1 year after CVE)'
            WHEN patch_exploit_gap > 365 THEN '> 365 days (More than 1 year after CVE)'
            ELSE 'Unknown'
        END AS time_gap_category
    FROM unified_exploit_patch_gaps
),
-- Calculate statistics for each category (count, avg, median, mode)
categorized_stats AS (
    SELECT
        time_gap_category,
        COUNT(cve_id) AS cve_count,
        CAST(AVG(patch_exploit_gap) AS DECIMAL(10, 2)) AS avg_patch_exploit_gap,
        CAST(MEDIAN(patch_exploit_gap) AS DECIMAL(10, 2)) AS median_patch_exploit_gap,
        -- Subquery to calculate mode for the current category
        (
            SELECT patch_exploit_gap
            FROM categorized_gaps_with_mode_input AS sub
            WHERE sub.time_gap_category = categorized_gaps_with_mode_input.time_gap_category
            GROUP BY patch_exploit_gap
            ORDER BY COUNT(*) DESC, patch_exploit_gap ASC
            LIMIT 1
        ) AS mode_patch_exploit_gap
    FROM categorized_gaps_with_mode_input
    GROUP BY time_gap_category
),
-- Calculate overall statistics (count, avg, median, mode)
overall_stats AS (
    SELECT
        'Overall Distribution' AS time_gap_category,
        COUNT(cve_id) AS cve_count,
        CAST(AVG(patch_exploit_gap) AS DECIMAL(10, 2)) AS avg_patch_exploit_gap,
        CAST(MEDIAN(patch_exploit_gap) AS DECIMAL(10, 2)) AS median_patch_exploit_gap,
        -- Subquery to calculate overall mode
        (
            SELECT patch_exploit_gap
            FROM unified_exploit_patch_gaps
            GROUP BY patch_exploit_gap
            ORDER BY COUNT(*) DESC, patch_exploit_gap ASC
            LIMIT 1
        ) AS mode_patch_exploit_gap
    FROM unified_exploit_patch_gaps
)
-- Wrap the UNION ALL in a subquery (derived table) and then apply ORDER BY
SELECT *
FROM (
    SELECT * FROM categorized_stats
    UNION ALL
    SELECT * FROM overall_stats
) AS combined_results
ORDER BY
    CASE
        WHEN time_gap_category = '< -365 days (More than 1 year before CVE)' THEN 1
        WHEN time_gap_category = '-365 to -181 days (6 months to 1 year before CVE)' THEN 2
        WHEN time_gap_category = '-180 to -91 days (3 to 6 months before CVE)' THEN 3
        WHEN time_gap_category = '-90 to -31 days (1 to 3 months before CVE)' THEN 4
        WHEN time_gap_category = '-30 to -1 days (Up to 1 month before CVE)' THEN 5
        WHEN time_gap_category = '0 days (Same day as CVE)' THEN 6
        WHEN time_gap_category = '1 to 30 days (Up to 1 month after CVE)' THEN 7
        WHEN time_gap_category = '31 to 90 days (1 to 3 months after CVE)' THEN 8
        WHEN time_gap_category = '91 to 180 days (3 to 6 months after CVE)' THEN 9
        WHEN time_gap_category = '181 to 365 days (6 months to 1 year after CVE)' THEN 10
        WHEN time_gap_category = '> 365 days (More than 1 year after CVE)' THEN 11
        WHEN time_gap_category = 'Unknown' THEN 12
        WHEN time_gap_category = 'Overall Distribution' THEN 100 -- Ensures overall row appears last
        ELSE 101 -- Fallback for any unexpected categories
    END;
```

* **Superset Chart Type**: Histogram  
* **Superset Configuration**:  
  * **Metric**: patch_exploit_gap  
  * **Binning**: Adjust bin size as needed (e.g., 30 days)

### **Ch5_Fig_5.11_Gap between exploit and patch dates for Microsoft-related CVEs (2016-2025)**

* **Question Answered**: For Microsoft-related CVEs, what percentage are patched before they are exploited?  
* **SQL Query**:  
```sql
WITH microsoft_cves_with_patch_and_exploit AS (
    SELECT DISTINCT cm.cve_id
    FROM cve_main cm
    CROSS JOIN UNNEST(STRING_SPLIT(cm.cpes, ',')) AS cpe_unnest(cpe_entry)
    JOIN msrc_patches mp ON cm.cve_id = mp.cve_id
    JOIN exploits e ON cm.cve_id = e.cve_id
    WHERE LOWER(SPLIT_PART(cpe_entry, ':', 4)) = 'microsoft'
        AND cm.state = 'PUBLISHED'
        AND cm.date_reserved IS NOT NULL
        AND mp.initial_release_date IS NOT NULL
        AND e.date_published IS NOT NULL
        AND mp.initial_release_date <= CURRENT_DATE
        AND e.date_published <= CURRENT_DATE
),
indexed_cves AS (
    SELECT
        cm.cve_id,
        cm.date_reserved,
        e.date_published AS exploit_published_date,
        ROW_NUMBER() OVER (ORDER BY cm.date_reserved ASC) AS cve_index
    FROM cve_main cm
    JOIN exploits e ON cm.cve_id = e.cve_id
    WHERE cm.cve_id IN (SELECT cve_id FROM microsoft_cves_with_patch_and_exploit)
)
SELECT
    cve_id,
    date_reserved AS date_value,
    'CVE Reserve Date' AS date_type,
    cve_index
FROM indexed_cves

UNION ALL

SELECT
    cve_id,
    exploit_published_date AS date_value,
    'Exploit Published Date' AS date_type,
    cve_index
FROM indexed_cves
ORDER BY cve_index, date_type;
```

* **Superset Chart Type**: Line Chart  
* **Superset Configuration**:  
  * **Set X-Axis to** date_value.
  * **Set Y-Axis to** cve_index.
  * **Set Group by / Series to** date_type.


### **Ch5_Fig_5.11_Gap between exploit and patch dates for All Vendors CVEs (2016-2025)**

* **Question Answered**: For all vendor CVEs, what percentage are patched before they are exploited across the ecosystem? 
* **SQL Query**: 

```sql
WITH all_cves_with_patch_and_exploit AS (
    SELECT DISTINCT cm.cve_id
    FROM cve_main cm
    WHERE cm.state = 'PUBLISHED'
        AND cm.date_reserved IS NOT NULL
        AND cm.date_reserved <= CURRENT_DATE
        AND EXISTS (
            SELECT 1 FROM msrc_patches mp
            WHERE mp.cve_id = cm.cve_id AND mp.initial_release_date IS NOT NULL AND mp.initial_release_date <= CURRENT_DATE
            UNION ALL
            SELECT 1 FROM redhat_patches rp
            WHERE rp.cve_id = cm.cve_id AND rp.initial_release_date IS NOT NULL AND rp.initial_release_date <= CURRENT_DATE
                AND (LOWER(rp.product_name) LIKE '%rhel%' OR LOWER(rp.product_name) LIKE '%red hat%' OR LOWER(rp.product_name) LIKE '%enterprise linux%')
            UNION ALL
            SELECT 1 FROM cisco_patches cp
            WHERE cp.cve_id = cm.cve_id AND cp.initial_release_date IS NOT NULL AND cp.initial_release_date <= CURRENT_DATE
        )
        AND EXISTS (
            SELECT 1 FROM exploits e
            WHERE e.cve_id = cm.cve_id AND e.date_published IS NOT NULL AND e.date_published <= CURRENT_DATE
        )
),
indexed_cves AS (
    SELECT
        cm.cve_id,
        cm.date_reserved,
        e.date_published AS exploit_published_date,
        ROW_NUMBER() OVER (ORDER BY cm.date_reserved ASC) AS cve_index
    FROM cve_main cm
    JOIN exploits e ON cm.cve_id = e.cve_id
    WHERE cm.cve_id IN (SELECT cve_id FROM all_cves_with_patch_and_exploit)
)
SELECT
    cve_id,
    date_reserved AS date_value,
    'CVE Reserve Date' AS date_type,
    cve_index
FROM indexed_cves

UNION ALL

SELECT
    cve_id,
    exploit_published_date AS date_value,
    'Exploit Published Date' AS date_type,
    cve_index
FROM indexed_cves
ORDER BY cve_index, date_type;
```
* **Superset Chart Type**: Line Chart  
* **Superset Configuration**:  
  * **Set X-Axis to** date_value.
  * **Set Y-Axis to** cve_index.
  * **Set Group by / Series to** date_type.

### **Ch5_Tab_5.1_Lifecycle Events Differences by Severity (Days)**

* **Question Answered**: How do the time differences between lifecycle events (disclosure, exploit, patch) vary across different severity levels?  
* **SQL Query**: (This query uses msrc_patches for Microsoft-specific data as per the original table.)  
```sql
WITH microsoft_cves_with_patch_and_exploit AS (
    SELECT DISTINCT 
        mp.cve_id,
        cm.date_reserved,
        mp.initial_release_date,
        -- Prioritize CVSS versions: v4 -> v3 -> v2
        CASE 
            WHEN cm.cvss_v4_score IS NOT NULL AND cm.cvss_v4_score != -1 THEN
                CASE 
                    WHEN cm.cvss_v4_score >= 9.0 THEN 'CRITICAL'
                    WHEN cm.cvss_v4_score >= 7.0 THEN 'HIGH'
                    WHEN cm.cvss_v4_score >= 4.0 THEN 'MEDIUM'
                    WHEN cm.cvss_v4_score > 0.0 THEN 'LOW'
                END
            WHEN cm.cvss_v3_score IS NOT NULL AND cm.cvss_v3_score != -1 THEN
                CASE 
                    WHEN cm.cvss_v3_score >= 9.0 THEN 'CRITICAL'
                    WHEN cm.cvss_v3_score >= 7.0 THEN 'HIGH'
                    WHEN cm.cvss_v3_score >= 4.0 THEN 'MEDIUM'
                    WHEN cm.cvss_v3_score > 0.0 THEN 'LOW'
                END
            WHEN cm.cvss_v2_score IS NOT NULL AND cm.cvss_v2_score != -1 THEN
                CASE 
                    WHEN cm.cvss_v2_score >= 7.0 THEN 'HIGH'
                    WHEN cm.cvss_v2_score >= 4.0 THEN 'MEDIUM'
                    WHEN cm.cvss_v2_score > 0.0 THEN 'LOW'
                END
            ELSE NULL
        END AS severity_level
    FROM msrc_patches mp
    JOIN cve_main cm ON mp.cve_id = cm.cve_id
    JOIN exploits e ON mp.cve_id = e.cve_id
    WHERE cm.state = 'PUBLISHED'
        AND cm.date_reserved IS NOT NULL
        AND mp.initial_release_date IS NOT NULL
        AND e.date_published IS NOT NULL
        AND mp.initial_release_date >= '2016-01-01'
        AND mp.initial_release_date <= '2025-05-13'
        AND e.date_published <= '2025-05-13'
),
lifecycle_timing AS (
    SELECT 
        mc.cve_id,
        mc.severity_level,
        mc.date_reserved,
        e.date_published as exploit_date,
        mc.initial_release_date as patch_date,
        DATE_DIFF('day', mc.date_reserved, e.date_published) AS exploit_creation_gap,
        DATE_DIFF('day', e.date_published, mc.initial_release_date) AS patch_exploit_gap,
        DATE_DIFF('day', mc.date_reserved, mc.initial_release_date) AS patch_creation_gap
    FROM microsoft_cves_with_patch_and_exploit mc
    JOIN exploits e ON mc.cve_id = e.cve_id
    WHERE mc.severity_level IS NOT NULL
),
event_stats AS (
    SELECT 
        'Exploit - Creation' AS event_type,
        severity_level,
        ROUND(AVG(exploit_creation_gap), 1) AS mean_days,
        ROUND(MEDIAN(exploit_creation_gap), 1) AS median_days,
        MODE(exploit_creation_gap) AS mode_days,
        COUNT(*) AS sample_size
    FROM lifecycle_timing
    GROUP BY severity_level
    
    UNION ALL
    
    SELECT 
        'Patch - Exploit' AS event_type,
        severity_level,
        ROUND(AVG(patch_exploit_gap), 1) AS mean_days,
        ROUND(MEDIAN(patch_exploit_gap), 1) AS median_days,
        MODE(patch_exploit_gap) AS mode_days,
        COUNT(*) AS sample_size
    FROM lifecycle_timing
    GROUP BY severity_level
    
    UNION ALL
    
    SELECT 
        'Patch - Creation' AS event_type,
        severity_level,
        ROUND(AVG(patch_creation_gap), 1) AS mean_days,
        ROUND(MEDIAN(patch_creation_gap), 1) AS median_days,
        MODE(patch_creation_gap) AS mode_days,
        COUNT(*) AS sample_size
    FROM lifecycle_timing
    GROUP BY severity_level
)
SELECT 
    event_type,
    COALESCE(MAX(CASE WHEN severity_level = 'CRITICAL' THEN CONCAT('μ:', mean_days, ' m:', median_days, ' mo:', mode_days) END), 'N/A') AS critical,
    COALESCE(MAX(CASE WHEN severity_level = 'HIGH' THEN CONCAT('μ:', mean_days, ' m:', median_days, ' mo:', mode_days) END), 'N/A') AS high,
    COALESCE(MAX(CASE WHEN severity_level = 'MEDIUM' THEN CONCAT('μ:', mean_days, ' m:', median_days, ' mo:', mode_days) END), 'N/A') AS medium,
    COALESCE(MAX(CASE WHEN severity_level = 'LOW' THEN CONCAT('μ:', mean_days, ' m:', median_days, ' mo:', mode_days) END), 'N/A') AS low
FROM event_stats
GROUP BY event_type
ORDER BY 
    CASE event_type
        WHEN 'Exploit - Creation' THEN 1
        WHEN 'Patch - Exploit' THEN 2
        WHEN 'Patch - Creation' THEN 3
    END;
```

* **Superset Chart Type**: Table  
* **Superset Configuration**:  
  * **Columns**: severity_level, median_exploit_creation_gap, median_patch_exploit_gap, median_patch_creation_gap

### **Ch5_Tab_5.1_Multi_Vendor_Lifecycle Events Differences by Severity (Days)**

* **Question Answered**: How do the time differences between lifecycle events vary across different severity levels for all vendors?


```sql
WITH all_cves_with_patch_and_exploit AS (
    -- Microsoft
    SELECT DISTINCT 
        mp.cve_id,
        cm.date_reserved,
        mp.initial_release_date as patch_date,
        'Microsoft' as vendor,
        CASE 
            WHEN cm.cvss_v4_score IS NOT NULL AND cm.cvss_v4_score != -1 THEN
                CASE 
                    WHEN cm.cvss_v4_score >= 9.0 THEN 'CRITICAL'
                    WHEN cm.cvss_v4_score >= 7.0 THEN 'HIGH'
                    WHEN cm.cvss_v4_score >= 4.0 THEN 'MEDIUM'
                    WHEN cm.cvss_v4_score > 0.0 THEN 'LOW'
                END
            WHEN cm.cvss_v3_score IS NOT NULL AND cm.cvss_v3_score != -1 THEN
                CASE 
                    WHEN cm.cvss_v3_score >= 9.0 THEN 'CRITICAL'
                    WHEN cm.cvss_v3_score >= 7.0 THEN 'HIGH'
                    WHEN cm.cvss_v3_score >= 4.0 THEN 'MEDIUM'
                    WHEN cm.cvss_v3_score > 0.0 THEN 'LOW'
                END
            WHEN cm.cvss_v2_score IS NOT NULL AND cm.cvss_v2_score != -1 THEN
                CASE 
                    WHEN cm.cvss_v2_score >= 7.0 THEN 'HIGH'
                    WHEN cm.cvss_v2_score >= 4.0 THEN 'MEDIUM'
                    WHEN cm.cvss_v2_score > 0.0 THEN 'LOW'
                END
            ELSE NULL
        END AS severity_level
    FROM msrc_patches mp
    JOIN cve_main cm ON mp.cve_id = cm.cve_id
    JOIN exploits e ON mp.cve_id = e.cve_id
    WHERE cm.state = 'PUBLISHED'
        AND mp.initial_release_date >= '2016-01-01'
        AND mp.initial_release_date <= '2025-05-13'
    
    UNION ALL
    
    -- RedHat
    SELECT DISTINCT 
        rp.cve_id,
        cm.date_reserved,
        rp.initial_release_date as patch_date,
        'RedHat' as vendor,
        CASE 
            WHEN cm.cvss_v4_score IS NOT NULL AND cm.cvss_v4_score != -1 THEN
                CASE 
                    WHEN cm.cvss_v4_score >= 9.0 THEN 'CRITICAL'
                    WHEN cm.cvss_v4_score >= 7.0 THEN 'HIGH'
                    WHEN cm.cvss_v4_score >= 4.0 THEN 'MEDIUM'
                    WHEN cm.cvss_v4_score > 0.0 THEN 'LOW'
                END
            WHEN cm.cvss_v3_score IS NOT NULL AND cm.cvss_v3_score != -1 THEN
                CASE 
                    WHEN cm.cvss_v3_score >= 9.0 THEN 'CRITICAL'
                    WHEN cm.cvss_v3_score >= 7.0 THEN 'HIGH'
                    WHEN cm.cvss_v3_score >= 4.0 THEN 'MEDIUM'
                    WHEN cm.cvss_v3_score > 0.0 THEN 'LOW'
                END
            WHEN cm.cvss_v2_score IS NOT NULL AND cm.cvss_v2_score != -1 THEN
                CASE 
                    WHEN cm.cvss_v2_score >= 7.0 THEN 'HIGH'
                    WHEN cm.cvss_v2_score >= 4.0 THEN 'MEDIUM'
                    WHEN cm.cvss_v2_score > 0.0 THEN 'LOW'
                END
            ELSE NULL
        END AS severity_level
    FROM redhat_patches rp
    JOIN cve_main cm ON rp.cve_id = cm.cve_id
    JOIN exploits e ON rp.cve_id = e.cve_id
    WHERE cm.state = 'PUBLISHED'
        AND rp.initial_release_date >= '2016-01-01'
        AND rp.initial_release_date <= '2025-05-13'
        AND (LOWER(rp.product_name) LIKE '%rhel%' OR LOWER(rp.product_name) LIKE '%red hat%' OR LOWER(rp.product_name) LIKE '%enterprise linux%')
    
    UNION ALL
    
    -- Cisco
    SELECT DISTINCT 
        cp.cve_id,
        cm.date_reserved,
        cp.initial_release_date as patch_date,
        'Cisco' as vendor,
        CASE 
            WHEN cm.cvss_v4_score IS NOT NULL AND cm.cvss_v4_score != -1 THEN
                CASE 
                    WHEN cm.cvss_v4_score >= 9.0 THEN 'CRITICAL'
                    WHEN cm.cvss_v4_score >= 7.0 THEN 'HIGH'
                    WHEN cm.cvss_v4_score >= 4.0 THEN 'MEDIUM'
                    WHEN cm.cvss_v4_score > 0.0 THEN 'LOW'
                END
            WHEN cm.cvss_v3_score IS NOT NULL AND cm.cvss_v3_score != -1 THEN
                CASE 
                    WHEN cm.cvss_v3_score >= 9.0 THEN 'CRITICAL'
                    WHEN cm.cvss_v3_score >= 7.0 THEN 'HIGH'
                    WHEN cm.cvss_v3_score >= 4.0 THEN 'MEDIUM'
                    WHEN cm.cvss_v3_score > 0.0 THEN 'LOW'
                END
            WHEN cm.cvss_v2_score IS NOT NULL AND cm.cvss_v2_score != -1 THEN
                CASE 
                    WHEN cm.cvss_v2_score >= 7.0 THEN 'HIGH'
                    WHEN cm.cvss_v2_score >= 4.0 THEN 'MEDIUM'
                    WHEN cm.cvss_v2_score > 0.0 THEN 'LOW'
                END
            ELSE NULL
        END AS severity_level
    FROM cisco_patches cp
    JOIN cve_main cm ON cp.cve_id = cm.cve_id
    JOIN exploits e ON cp.cve_id = e.cve_id
    WHERE cm.state = 'PUBLISHED'
        AND cp.initial_release_date >= '2016-01-01'
        AND cp.initial_release_date <= '2025-05-13'
),
unified_lifecycle_timing AS (
    SELECT 
        ac.cve_id,
        ac.severity_level,
        ac.date_reserved,
        e.date_published as exploit_date,
        ac.patch_date,
        DATE_DIFF('day', ac.date_reserved, e.date_published) AS exploit_creation_gap,
        DATE_DIFF('day', e.date_published, ac.patch_date) AS patch_exploit_gap,
        DATE_DIFF('day', ac.date_reserved, ac.patch_date) AS patch_creation_gap
    FROM all_cves_with_patch_and_exploit ac
    JOIN exploits e ON ac.cve_id = e.cve_id
    WHERE ac.severity_level IS NOT NULL
        AND ac.date_reserved IS NOT NULL
        AND e.date_published IS NOT NULL
        AND e.date_published <= '2025-05-13'
),
event_stats AS (
    SELECT 
        'Exploit - Creation' AS event_type,
        severity_level,
        ROUND(AVG(exploit_creation_gap), 1) AS mean_days,
        ROUND(MEDIAN(exploit_creation_gap), 1) AS median_days,
        MODE(exploit_creation_gap) AS mode_days,
        COUNT(*) AS sample_size
    FROM unified_lifecycle_timing
    GROUP BY severity_level
    
    UNION ALL
    
    SELECT 
        'Patch - Exploit' AS event_type,
        severity_level,
        ROUND(AVG(patch_exploit_gap), 1) AS mean_days,
        ROUND(MEDIAN(patch_exploit_gap), 1) AS median_days,
        MODE(patch_exploit_gap) AS mode_days,
        COUNT(*) AS sample_size
    FROM unified_lifecycle_timing
    GROUP BY severity_level
    
    UNION ALL
    
    SELECT 
        'Patch - Creation' AS event_type,
        severity_level,
        ROUND(AVG(patch_creation_gap), 1) AS mean_days,
        ROUND(MEDIAN(patch_creation_gap), 1) AS median_days,
        MODE(patch_creation_gap) AS mode_days,
        COUNT(*) AS sample_size
    FROM unified_lifecycle_timing
    GROUP BY severity_level
)
SELECT 
    event_type,
    COALESCE(MAX(CASE WHEN severity_level = 'CRITICAL' THEN CONCAT('μ:', mean_days, ' m:', median_days, ' mo:', mode_days) END), 'N/A') AS critical,
    COALESCE(MAX(CASE WHEN severity_level = 'HIGH' THEN CONCAT('μ:', mean_days, ' m:', median_days, ' mo:', mode_days) END), 'N/A') AS high,
    COALESCE(MAX(CASE WHEN severity_level = 'MEDIUM' THEN CONCAT('μ:', mean_days, ' m:', median_days, ' mo:', mode_days) END), 'N/A') AS medium,
    COALESCE(MAX(CASE WHEN severity_level = 'LOW' THEN CONCAT('μ:', mean_days, ' m:', median_days, ' mo:', mode_days) END), 'N/A') AS low
FROM event_stats
GROUP BY event_type
ORDER BY 
    CASE event_type
        WHEN 'Exploit - Creation' THEN 1
        WHEN 'Patch - Exploit' THEN 2
        WHEN 'Patch - Creation' THEN 3
    END;
```
### **Ch5_Fig_5.12_Yearly trend of mean and median time differences for Critical severity across all events**

* **Question Answered**: What is the yearly trend for lifecycle event timing for Critical severity vulnerabilities?  
* **SQL Query**: (This query uses msrc_patches for Microsoft-specific data. You could adapt it to use unified_patches for an overall view.)  
```sql
WITH microsoft_cves_with_patch_and_exploit AS (
    SELECT DISTINCT 
        mp.cve_id,
        cm.date_reserved,
        mp.initial_release_date,
        -- Prioritize CVSS versions: v4 -> v3 -> v2
        CASE 
            WHEN cm.cvss_v4_score IS NOT NULL AND cm.cvss_v4_score != -1 THEN
                CASE 
                    WHEN cm.cvss_v4_score >= 9.0 THEN 'CRITICAL'
                    WHEN cm.cvss_v4_score >= 7.0 THEN 'HIGH'
                    WHEN cm.cvss_v4_score >= 4.0 THEN 'MEDIUM'
                    WHEN cm.cvss_v4_score > 0.0 THEN 'LOW'
                END
            WHEN cm.cvss_v3_score IS NOT NULL AND cm.cvss_v3_score != -1 THEN
                CASE 
                    WHEN cm.cvss_v3_score >= 9.0 THEN 'CRITICAL'
                    WHEN cm.cvss_v3_score >= 7.0 THEN 'HIGH'
                    WHEN cm.cvss_v3_score >= 4.0 THEN 'MEDIUM'
                    WHEN cm.cvss_v3_score > 0.0 THEN 'LOW'
                END
            WHEN cm.cvss_v2_score IS NOT NULL AND cm.cvss_v2_score != -1 THEN
                CASE 
                    WHEN cm.cvss_v2_score >= 7.0 THEN 'HIGH'
                    WHEN cm.cvss_v2_score >= 4.0 THEN 'MEDIUM'
                    WHEN cm.cvss_v2_score > 0.0 THEN 'LOW'
                END
            ELSE NULL
        END AS severity_level
    FROM msrc_patches mp
    JOIN cve_main cm ON mp.cve_id = cm.cve_id
    JOIN exploits e ON mp.cve_id = e.cve_id
    WHERE cm.state = 'PUBLISHED'
        AND cm.date_reserved IS NOT NULL
        AND mp.initial_release_date IS NOT NULL
        AND e.date_published IS NOT NULL
        AND mp.initial_release_date >= '2016-01-01'
        AND mp.initial_release_date <= '2025-05-13'
        AND e.date_published <= '2025-05-13'
),
yearly_lifecycle_timing AS (
    SELECT 
        STRFTIME(cm.date_reserved, '%Y') AS year,
        mc.severity_level,
        DATE_DIFF('day', mc.date_reserved, e.date_published) AS exploit_creation_gap,
        DATE_DIFF('day', e.date_published, mc.initial_release_date) AS patch_exploit_gap,
        DATE_DIFF('day', mc.date_reserved, mc.initial_release_date) AS patch_creation_gap
    FROM microsoft_cves_with_patch_and_exploit mc
    JOIN cve_main cm ON mc.cve_id = cm.cve_id
    JOIN exploits e ON mc.cve_id = e.cve_id
    WHERE mc.severity_level = 'CRITICAL'
        AND STRFTIME(cm.date_reserved, '%Y') >= '2016'
),
yearly_stats AS (
    SELECT 
        year,
        'Exploit - Creation (Mean)' AS event_metric,
        ROUND(AVG(exploit_creation_gap), 1) AS days_value
    FROM yearly_lifecycle_timing
    GROUP BY year
    
    UNION ALL
    
    SELECT 
        year,
        'Exploit - Creation (Median)' AS event_metric,
        ROUND(MEDIAN(exploit_creation_gap), 1) AS days_value
    FROM yearly_lifecycle_timing
    GROUP BY year
    
    UNION ALL
    
    SELECT 
        year,
        'Patch - Exploit (Mean)' AS event_metric,
        ROUND(AVG(patch_exploit_gap), 1) AS days_value
    FROM yearly_lifecycle_timing
    GROUP BY year
    
    UNION ALL
    
    SELECT 
        year,
        'Patch - Exploit (Median)' AS event_metric,
        ROUND(MEDIAN(patch_exploit_gap), 1) AS days_value
    FROM yearly_lifecycle_timing
    GROUP BY year
    
    UNION ALL
    
    SELECT 
        year,
        'Patch - Creation (Mean)' AS event_metric,
        ROUND(AVG(patch_creation_gap), 1) AS days_value
    FROM yearly_lifecycle_timing
    GROUP BY year
    
    UNION ALL
    
    SELECT 
        year,
        'Patch - Creation (Median)' AS event_metric,
        ROUND(MEDIAN(patch_creation_gap), 1) AS days_value
    FROM yearly_lifecycle_timing
    GROUP BY year
)
SELECT 
    year,
    event_metric,
    days_value
FROM yearly_stats
ORDER BY year, event_metric;
```

* **Superset Chart Type**: Line Chart  
* **Superset Configuration**:  
  * **X-axis**: year  
  * **Y-axis**: median_days (and/or mean_days as separate series)  
  * **Group By**: event_type  
  * **Time Range**: Custom, 2016-01-01 to 2025-05-13  
  * **Filters**: severity_level = 'CRITICAL' (if not already filtered in SQL)

### **Ch5_Fig_5.12_Multi-vendors_Yearly trend of mean and median time differences for Critical severity across all events**

* **Question Answered**: What is the yearly trend for lifecycle event timing for Critical severity vulnerabilities for all vendors?  
* **SQL Query**: ( Adapt it to use unified_patches for an overall view.) 
```sql
WITH all_cves_with_patch_and_exploit AS (
    -- Microsoft
    SELECT DISTINCT 
        mp.cve_id,
        cm.date_reserved,
        mp.initial_release_date as patch_date,
        CASE 
            WHEN cm.cvss_v4_score IS NOT NULL AND cm.cvss_v4_score != -1 THEN
                CASE 
                    WHEN cm.cvss_v4_score >= 9.0 THEN 'CRITICAL'
                    WHEN cm.cvss_v4_score >= 7.0 THEN 'HIGH'
                    WHEN cm.cvss_v4_score >= 4.0 THEN 'MEDIUM'
                    WHEN cm.cvss_v4_score > 0.0 THEN 'LOW'
                END
            WHEN cm.cvss_v3_score IS NOT NULL AND cm.cvss_v3_score != -1 THEN
                CASE 
                    WHEN cm.cvss_v3_score >= 9.0 THEN 'CRITICAL'
                    WHEN cm.cvss_v3_score >= 7.0 THEN 'HIGH'
                    WHEN cm.cvss_v3_score >= 4.0 THEN 'MEDIUM'
                    WHEN cm.cvss_v3_score > 0.0 THEN 'LOW'
                END
            WHEN cm.cvss_v2_score IS NOT NULL AND cm.cvss_v2_score != -1 THEN
                CASE 
                    WHEN cm.cvss_v2_score >= 7.0 THEN 'HIGH'
                    WHEN cm.cvss_v2_score >= 4.0 THEN 'MEDIUM'
                    WHEN cm.cvss_v2_score > 0.0 THEN 'LOW'
                END
            ELSE NULL
        END AS severity_level
    FROM msrc_patches mp
    JOIN cve_main cm ON mp.cve_id = cm.cve_id
    JOIN exploits e ON mp.cve_id = e.cve_id
    WHERE cm.state = 'PUBLISHED'
        AND mp.initial_release_date >= '2016-01-01'
        AND mp.initial_release_date <= '2025-05-13'
    
    UNION ALL
    
    -- RedHat
    SELECT DISTINCT 
        rp.cve_id,
        cm.date_reserved,
        rp.initial_release_date as patch_date,
        CASE 
            WHEN cm.cvss_v4_score IS NOT NULL AND cm.cvss_v4_score != -1 THEN
                CASE 
                    WHEN cm.cvss_v4_score >= 9.0 THEN 'CRITICAL'
                    WHEN cm.cvss_v4_score >= 7.0 THEN 'HIGH'
                    WHEN cm.cvss_v4_score >= 4.0 THEN 'MEDIUM'
                    WHEN cm.cvss_v4_score > 0.0 THEN 'LOW'
                END
            WHEN cm.cvss_v3_score IS NOT NULL AND cm.cvss_v3_score != -1 THEN
                CASE 
                    WHEN cm.cvss_v3_score >= 9.0 THEN 'CRITICAL'
                    WHEN cm.cvss_v3_score >= 7.0 THEN 'HIGH'
                    WHEN cm.cvss_v3_score >= 4.0 THEN 'MEDIUM'
                    WHEN cm.cvss_v3_score > 0.0 THEN 'LOW'
                END
            WHEN cm.cvss_v2_score IS NOT NULL AND cm.cvss_v2_score != -1 THEN
                CASE 
                    WHEN cm.cvss_v2_score >= 7.0 THEN 'HIGH'
                    WHEN cm.cvss_v2_score >= 4.0 THEN 'MEDIUM'
                    WHEN cm.cvss_v2_score > 0.0 THEN 'LOW'
                END
            ELSE NULL
        END AS severity_level
    FROM redhat_patches rp
    JOIN cve_main cm ON rp.cve_id = cm.cve_id
    JOIN exploits e ON rp.cve_id = e.cve_id
    WHERE cm.state = 'PUBLISHED'
        AND rp.initial_release_date >= '2016-01-01'
        AND rp.initial_release_date <= '2025-05-13'
        AND (LOWER(rp.product_name) LIKE '%rhel%' OR LOWER(rp.product_name) LIKE '%red hat%' OR LOWER(rp.product_name) LIKE '%enterprise linux%')
    
    UNION ALL
    
    -- Cisco
    SELECT DISTINCT 
        cp.cve_id,
        cm.date_reserved,
        cp.initial_release_date as patch_date,
        CASE 
            WHEN cm.cvss_v4_score IS NOT NULL AND cm.cvss_v4_score != -1 THEN
                CASE 
                    WHEN cm.cvss_v4_score >= 9.0 THEN 'CRITICAL'
                    WHEN cm.cvss_v4_score >= 7.0 THEN 'HIGH'
                    WHEN cm.cvss_v4_score >= 4.0 THEN 'MEDIUM'
                    WHEN cm.cvss_v4_score > 0.0 THEN 'LOW'
                END
            WHEN cm.cvss_v3_score IS NOT NULL AND cm.cvss_v3_score != -1 THEN
                CASE 
                    WHEN cm.cvss_v3_score >= 9.0 THEN 'CRITICAL'
                    WHEN cm.cvss_v3_score >= 7.0 THEN 'HIGH'
                    WHEN cm.cvss_v3_score >= 4.0 THEN 'MEDIUM'
                    WHEN cm.cvss_v3_score > 0.0 THEN 'LOW'
                END
            WHEN cm.cvss_v2_score IS NOT NULL AND cm.cvss_v2_score != -1 THEN
                CASE 
                    WHEN cm.cvss_v2_score >= 7.0 THEN 'HIGH'
                    WHEN cm.cvss_v2_score >= 4.0 THEN 'MEDIUM'
                    WHEN cm.cvss_v2_score > 0.0 THEN 'LOW'
                END
            ELSE NULL
        END AS severity_level
    FROM cisco_patches cp
    JOIN cve_main cm ON cp.cve_id = cm.cve_id
    JOIN exploits e ON cp.cve_id = e.cve_id
    WHERE cm.state = 'PUBLISHED'
        AND cp.initial_release_date >= '2016-01-01'
        AND cp.initial_release_date <= '2025-05-13'
),
yearly_lifecycle_timing AS (
    SELECT 
        STRFTIME(ac.date_reserved, '%Y') AS year,
        ac.severity_level,
        DATE_DIFF('day', ac.date_reserved, e.date_published) AS exploit_creation_gap,
        DATE_DIFF('day', e.date_published, ac.patch_date) AS patch_exploit_gap,
        DATE_DIFF('day', ac.date_reserved, ac.patch_date) AS patch_creation_gap
    FROM all_cves_with_patch_and_exploit ac
    JOIN exploits e ON ac.cve_id = e.cve_id
    WHERE ac.severity_level = 'CRITICAL'
        AND ac.date_reserved IS NOT NULL
        AND e.date_published IS NOT NULL
        AND e.date_published <= '2025-05-13'
        AND STRFTIME(ac.date_reserved, '%Y') >= '2016'
),
yearly_stats AS (
    SELECT 
        year,
        'Exploit - Creation (Mean)' AS event_metric,
        ROUND(AVG(exploit_creation_gap), 1) AS days_value
    FROM yearly_lifecycle_timing
    GROUP BY year
    
    UNION ALL
    
    SELECT 
        year,
        'Exploit - Creation (Median)' AS event_metric,
        ROUND(MEDIAN(exploit_creation_gap), 1) AS days_value
    FROM yearly_lifecycle_timing
    GROUP BY year
    
    UNION ALL
    
    SELECT 
        year,
        'Patch - Exploit (Mean)' AS event_metric,
        ROUND(AVG(patch_exploit_gap), 1) AS days_value
    FROM yearly_lifecycle_timing
    GROUP BY year
    
    UNION ALL
    
    SELECT 
        year,
        'Patch - Exploit (Median)' AS event_metric,
        ROUND(MEDIAN(patch_exploit_gap), 1) AS days_value
    FROM yearly_lifecycle_timing
    GROUP BY year
    
    UNION ALL
    
    SELECT 
        year,
        'Patch - Creation (Mean)' AS event_metric,
        ROUND(AVG(patch_creation_gap), 1) AS days_value
    FROM yearly_lifecycle_timing
    GROUP BY year
    
    UNION ALL
    
    SELECT 
        year,
        'Patch - Creation (Median)' AS event_metric,
        ROUND(MEDIAN(patch_creation_gap), 1) AS days_value
    FROM yearly_lifecycle_timing
    GROUP BY year
)
SELECT 
    year,
    event_metric,
    days_value
FROM yearly_stats
ORDER BY year, event_metric;
```

### **Ch5_Fig_5.13_Yearly trend of mean and median time differences for High severity across all events**

* **Question Answered**: What is the yearly trend for lifecycle event timing for High severity vulnerabilities?  
* **SQL Query**: (Same as above, replace CRITICAL with HIGH in WHERE clauses)  
```sql
Same structure as above, but with WHERE mc.severity_level = 'HIGH'
```

* **Superset Chart Type**: Line Chart  
* **Superset Configuration**:  
  * **X-axis**: year  
  * **Y-axis**: median_days (and/or mean_days as separate series)  
  * **Group By**: event_type  
  * **Time Range**: Custom, 2016-01-01 to 2025-05-13  
  * **Filters**: severity_level = 'HIGH'

### **Ch5_Fig_5.14_Yearly trend of mean and median time differences for Medium severity across all events**

* **Question Answered**: What is the yearly trend for lifecycle event timing for Medium severity vulnerabilities?  
* **SQL Query**: (Same as above, replace CRITICAL with MEDIUM in WHERE clauses)  
```sql
Same structure as above, but with WHERE mc.severity_level = 'MEDIUM'
```
* **Superset Chart Type**: Line Chart  
* **Superset Configuration**:  
  * **X-axis**: year  
  * **Y-axis**: median_days (and/or mean_days as separate series)  
  * **Group By**: event_type  
  * **Time Range**: Custom, 2016-01-01 to 2025-05-13  
  * **Filters**: severity_level = 'MEDIUM'

### **Ch5_Fig_5.15_Yearly trend of mean and median time differences for Low severity across all events**

* **Question Answered**: What is the yearly trend for lifecycle event timing for Low severity vulnerabilities?  
* **SQL Query**: (Same as above, replace CRITICAL with LOW in WHERE clauses)  
```sql
Same structure as above, but with WHERE mc.severity_level = 'LOW'
```

* **Superset Chart Type**: Line Chart  
* **Superset Configuration**:  
  * **X-axis**: year  
  * **Y-axis**: median_days (and/or mean_days as separate series)  
  * **Group By**: event_type  
  * **Time Range**: Custom, 2016-01-01 to 2025-05-13  
  * **Filters**: severity_level = 'LOW'

### **Ch5_Fig_5.16_Three-Way Comparison: Median Patching Times (in days) for All Microsoft Patched CVEs, Non-Exploited Patched CVEs, and Exploited Patched CVEs by Severity Level**

* **Question Answered**: How does the median time to patch differ for non-exploited vs. exploited vulnerabilities across severity levels?  
* **SQL Query**:  
```sql
WITH microsoft_patch_timing AS (
    -- All Microsoft Patched CVEs
    SELECT 
        mp.cve_id,
        cm.date_reserved,
        mp.initial_release_date,
        cm.has_exploit,
        CASE 
            WHEN cm.cvss_v4_score IS NOT NULL AND cm.cvss_v4_score != -1 THEN
                CASE 
                    WHEN cm.cvss_v4_score >= 9.0 THEN 'CRITICAL'
                    WHEN cm.cvss_v4_score >= 7.0 THEN 'HIGH'
                    WHEN cm.cvss_v4_score >= 4.0 THEN 'MEDIUM'
                    WHEN cm.cvss_v4_score > 0.0 THEN 'LOW'
                END
            WHEN cm.cvss_v3_score IS NOT NULL AND cm.cvss_v3_score != -1 THEN
                CASE 
                    WHEN cm.cvss_v3_score >= 9.0 THEN 'CRITICAL'
                    WHEN cm.cvss_v3_score >= 7.0 THEN 'HIGH'
                    WHEN cm.cvss_v3_score >= 4.0 THEN 'MEDIUM'
                    WHEN cm.cvss_v3_score > 0.0 THEN 'LOW'
                END
            WHEN cm.cvss_v2_score IS NOT NULL AND cm.cvss_v2_score != -1 THEN
                CASE 
                    WHEN cm.cvss_v2_score >= 7.0 THEN 'HIGH'
                    WHEN cm.cvss_v2_score >= 4.0 THEN 'MEDIUM'
                    WHEN cm.cvss_v2_score > 0.0 THEN 'LOW'
                END
            ELSE NULL
        END AS severity_level,
        DATE_DIFF('day', cm.date_reserved, mp.initial_release_date) AS days_to_patch
    FROM msrc_patches mp
    JOIN cve_main cm ON mp.cve_id = cm.cve_id
    WHERE cm.state = 'PUBLISHED'
        AND cm.date_reserved IS NOT NULL
        AND mp.initial_release_date IS NOT NULL
        AND mp.initial_release_date >= '2016-01-01'
        AND mp.initial_release_date <= '2025-05-13'
        AND cm.date_reserved <= mp.initial_release_date  -- Ensure patch comes after CVE
),
patch_categories AS (
    SELECT 
        severity_level,
        'All Microsoft Patched' AS category,
        ROUND(MEDIAN(days_to_patch), 1) AS median_days_to_patch,
        COUNT(*) AS sample_size
    FROM microsoft_patch_timing
    WHERE severity_level IS NOT NULL
        AND days_to_patch >= 0
    GROUP BY severity_level
    
    UNION ALL
    
    SELECT 
        severity_level,
        'Non-Exploited Patched' AS category,
        ROUND(MEDIAN(days_to_patch), 1) AS median_days_to_patch,
        COUNT(*) AS sample_size
    FROM microsoft_patch_timing
    WHERE severity_level IS NOT NULL
        AND has_exploit = 0
        AND days_to_patch >= 0
    GROUP BY severity_level
    
    UNION ALL
    
    SELECT 
        severity_level,
        'Exploited Patched' AS category,
        ROUND(MEDIAN(days_to_patch), 1) AS median_days_to_patch,
        COUNT(*) AS sample_size
    FROM microsoft_patch_timing
    WHERE severity_level IS NOT NULL
        AND has_exploit = 1
        AND days_to_patch >= 0
    GROUP BY severity_level
)
SELECT 
    severity_level,
    category,
    median_days_to_patch,
    sample_size
FROM patch_categories
ORDER BY 
    CASE severity_level 
        WHEN 'CRITICAL' THEN 1 
        WHEN 'HIGH' THEN 2 
        WHEN 'MEDIUM' THEN 3 
        WHEN 'LOW' THEN 4 
    END,
    CASE category
        WHEN 'All Microsoft Patched' THEN 1
        WHEN 'Non-Exploited Patched' THEN 2
        WHEN 'Exploited Patched' THEN 3
    END;
```

* **Superset Chart Type**: Grouped Bar Chart  
* **Superset Configuration**:  
  * **X-axis**: severity_level  
  * **Y-axis**: median_days_to_patch  
  * **Group By**: category  
  * **Sort By**: Custom order for severity (Critical, High, Medium, Low)

### **Ch5_Fig_5.16_Multi-vendor_Three-Way Comparison: Median Patching Times (in days) for All Microsoft Patched CVEs, Non-Exploited Patched CVEs, and Exploited Patched CVEs by Severity Level**

* **Question Answered**: How does the median time to patch differ for non-exploited vs. exploited vulnerabilities across severity levels for Multi-vendors?  

* **SQL Query**
```sql
WITH unified_patch_timing AS (
    -- Microsoft
    SELECT 
        mp.cve_id,
        cm.date_reserved,
        mp.initial_release_date as patch_date,
        cm.has_exploit,
        'Microsoft' as vendor,
        CASE 
            WHEN cm.cvss_v4_score IS NOT NULL AND cm.cvss_v4_score != -1 THEN
                CASE 
                    WHEN cm.cvss_v4_score >= 9.0 THEN 'CRITICAL'
                    WHEN cm.cvss_v4_score >= 7.0 THEN 'HIGH'
                    WHEN cm.cvss_v4_score >= 4.0 THEN 'MEDIUM'
                    WHEN cm.cvss_v4_score > 0.0 THEN 'LOW'
                END
            WHEN cm.cvss_v3_score IS NOT NULL AND cm.cvss_v3_score != -1 THEN
                CASE 
                    WHEN cm.cvss_v3_score >= 9.0 THEN 'CRITICAL'
                    WHEN cm.cvss_v3_score >= 7.0 THEN 'HIGH'
                    WHEN cm.cvss_v3_score >= 4.0 THEN 'MEDIUM'
                    WHEN cm.cvss_v3_score > 0.0 THEN 'LOW'
                END
            WHEN cm.cvss_v2_score IS NOT NULL AND cm.cvss_v2_score != -1 THEN
                CASE 
                    WHEN cm.cvss_v2_score >= 7.0 THEN 'HIGH'
                    WHEN cm.cvss_v2_score >= 4.0 THEN 'MEDIUM'
                    WHEN cm.cvss_v2_score > 0.0 THEN 'LOW'
                END
            ELSE NULL
        END AS severity_level,
        DATE_DIFF('day', cm.date_reserved, mp.initial_release_date) AS days_to_patch
    FROM msrc_patches mp
    JOIN cve_main cm ON mp.cve_id = cm.cve_id
    WHERE cm.state = 'PUBLISHED'
        AND cm.date_reserved IS NOT NULL
        AND mp.initial_release_date IS NOT NULL
        AND mp.initial_release_date >= '2016-01-01'
        AND mp.initial_release_date <= '2025-05-13'
    
    UNION ALL
    
    -- RedHat
    SELECT 
        rp.cve_id,
        cm.date_reserved,
        rp.initial_release_date as patch_date,
        cm.has_exploit,
        'RedHat' as vendor,
        CASE 
            WHEN cm.cvss_v4_score IS NOT NULL AND cm.cvss_v4_score != -1 THEN
                CASE 
                    WHEN cm.cvss_v4_score >= 9.0 THEN 'CRITICAL'
                    WHEN cm.cvss_v4_score >= 7.0 THEN 'HIGH'
                    WHEN cm.cvss_v4_score >= 4.0 THEN 'MEDIUM'
                    WHEN cm.cvss_v4_score > 0.0 THEN 'LOW'
                END
            WHEN cm.cvss_v3_score IS NOT NULL AND cm.cvss_v3_score != -1 THEN
                CASE 
                    WHEN cm.cvss_v3_score >= 9.0 THEN 'CRITICAL'
                    WHEN cm.cvss_v3_score >= 7.0 THEN 'HIGH'
                    WHEN cm.cvss_v3_score >= 4.0 THEN 'MEDIUM'
                    WHEN cm.cvss_v3_score > 0.0 THEN 'LOW'
                END
            WHEN cm.cvss_v2_score IS NOT NULL AND cm.cvss_v2_score != -1 THEN
                CASE 
                    WHEN cm.cvss_v2_score >= 7.0 THEN 'HIGH'
                    WHEN cm.cvss_v2_score >= 4.0 THEN 'MEDIUM'
                    WHEN cm.cvss_v2_score > 0.0 THEN 'LOW'
                END
            ELSE NULL
        END AS severity_level,
        DATE_DIFF('day', cm.date_reserved, rp.initial_release_date) AS days_to_patch
    FROM redhat_patches rp
    JOIN cve_main cm ON rp.cve_id = cm.cve_id
    WHERE cm.state = 'PUBLISHED'
        AND cm.date_reserved IS NOT NULL
        AND rp.initial_release_date IS NOT NULL
        AND rp.initial_release_date >= '2016-01-01'
        AND rp.initial_release_date <= '2025-05-13'
        AND (LOWER(rp.product_name) LIKE '%rhel%' OR LOWER(rp.product_name) LIKE '%red hat%' OR LOWER(rp.product_name) LIKE '%enterprise linux%')
    
    UNION ALL
    
    -- Cisco
    SELECT 
        cp.cve_id,
        cm.date_reserved,
        cp.initial_release_date as patch_date,
        cm.has_exploit,
        'Cisco' as vendor,
        CASE 
            WHEN cm.cvss_v4_score IS NOT NULL AND cm.cvss_v4_score != -1 THEN
                CASE 
                    WHEN cm.cvss_v4_score >= 9.0 THEN 'CRITICAL'
                    WHEN cm.cvss_v4_score >= 7.0 THEN 'HIGH'
                    WHEN cm.cvss_v4_score >= 4.0 THEN 'MEDIUM'
                    WHEN cm.cvss_v4_score > 0.0 THEN 'LOW'
                END
            WHEN cm.cvss_v3_score IS NOT NULL AND cm.cvss_v3_score != -1 THEN
                CASE 
                    WHEN cm.cvss_v3_score >= 9.0 THEN 'CRITICAL'
                    WHEN cm.cvss_v3_score >= 7.0 THEN 'HIGH'
                    WHEN cm.cvss_v3_score >= 4.0 THEN 'MEDIUM'
                    WHEN cm.cvss_v3_score > 0.0 THEN 'LOW'
                END
            WHEN cm.cvss_v2_score IS NOT NULL AND cm.cvss_v2_score != -1 THEN
                CASE 
                    WHEN cm.cvss_v2_score >= 7.0 THEN 'HIGH'
                    WHEN cm.cvss_v2_score >= 4.0 THEN 'MEDIUM'
                    WHEN cm.cvss_v2_score > 0.0 THEN 'LOW'
                END
            ELSE NULL
        END AS severity_level,
        DATE_DIFF('day', cm.date_reserved, cp.initial_release_date) AS days_to_patch
    FROM cisco_patches cp
    JOIN cve_main cm ON cp.cve_id = cm.cve_id
    WHERE cm.state = 'PUBLISHED'
        AND cm.date_reserved IS NOT NULL
        AND cp.initial_release_date IS NOT NULL
        AND cp.initial_release_date >= '2016-01-01'
        AND cp.initial_release_date <= '2025-05-13'
),
patch_categories AS (
    SELECT 
        severity_level,
        'All Vendor Patched' AS category,
        ROUND(MEDIAN(days_to_patch), 1) AS median_days_to_patch,
        COUNT(*) AS sample_size
    FROM unified_patch_timing
    WHERE severity_level IS NOT NULL
        AND days_to_patch >= 0
    GROUP BY severity_level
    
    UNION ALL
    
    SELECT 
        severity_level,
        'Non-Exploited Patched' AS category,
        ROUND(MEDIAN(days_to_patch), 1) AS median_days_to_patch,
        COUNT(*) AS sample_size
    FROM unified_patch_timing
    WHERE severity_level IS NOT NULL
        AND has_exploit = 0
        AND days_to_patch >= 0
    GROUP BY severity_level
    
    UNION ALL
    
    SELECT 
        severity_level,
        'Exploited Patched' AS category,
        ROUND(MEDIAN(days_to_patch), 1) AS median_days_to_patch,
        COUNT(*) AS sample_size
    FROM unified_patch_timing
    WHERE severity_level IS NOT NULL
        AND has_exploit = 1
        AND days_to_patch >= 0
    GROUP BY severity_level
)
SELECT 
    severity_level,
    category,
    median_days_to_patch,
    sample_size
FROM patch_categories
ORDER BY 
    CASE severity_level 
        WHEN 'CRITICAL' THEN 1 
        WHEN 'HIGH' THEN 2 
        WHEN 'MEDIUM' THEN 3 
        WHEN 'LOW' THEN 4 
    END,
    CASE category
        WHEN 'All Vendor Patched' THEN 1
        WHEN 'Non-Exploited Patched' THEN 2
        WHEN 'Exploited Patched' THEN 3
    END;
```
### **Ch5_Tab_5.2_CVE with more than 1000 days between Exploitation and CVE Creation Date(Microsoft)**

* **Question Answered**: Which CVEs have extremely long gaps (>1000 days) between CVE creation and exploit publication?  

* **SQL Query**:
```sql
WITH long_exploit_gaps AS (
    SELECT
        cm.cve_id,
        cm.date_reserved,
        e.date_published as exploit_date,
        DATE_DIFF('day', cm.date_reserved, e.date_published) AS days_to_exploit,
        -- Prioritize CVSS versions: v4 -> v3 -> v2
        COALESCE(
            CASE WHEN cm.cvss_v4_score IS NOT NULL AND cm.cvss_v4_score != -1 THEN cm.cvss_v4_score END,
            CASE WHEN cm.cvss_v3_score IS NOT NULL AND cm.cvss_v3_score != -1 THEN cm.cvss_v3_score END,
            CASE WHEN cm.cvss_v2_score IS NOT NULL AND cm.cvss_v2_score != -1 THEN cm.cvss_v2_score END
        ) AS cvss_score,
        CASE
            WHEN cm.cvss_v4_score IS NOT NULL AND cm.cvss_v4_score != -1 THEN 'v4'
            WHEN cm.cvss_v3_score IS NOT NULL AND cm.cvss_v3_score != -1 THEN 'v3'
            WHEN cm.cvss_v2_score IS NOT NULL AND cm.cvss_v2_score != -1 THEN 'v2'
            ELSE 'N/A'
        END AS cvss_version,
        CASE
            WHEN cm.cvss_v4_score IS NOT NULL AND cm.cvss_v4_score != -1 THEN
                CASE
                    WHEN cm.cvss_v4_score >= 9.0 THEN 'CRITICAL'
                    WHEN cm.cvss_v4_score >= 7.0 THEN 'HIGH'
                    WHEN cm.cvss_v4_score >= 4.0 THEN 'MEDIUM'
                    WHEN cm.cvss_v4_score > 0.0 THEN 'LOW'
                END
            WHEN cm.cvss_v3_score IS NOT NULL AND cm.cvss_v3_score != -1 THEN
                CASE
                    WHEN cm.cvss_v3_score >= 9.0 THEN 'CRITICAL'
                    WHEN cm.cvss_v3_score >= 7.0 THEN 'HIGH'
                    WHEN cm.cvss_v3_score >= 4.0 THEN 'MEDIUM'
                    WHEN cm.cvss_v3_score > 0.0 THEN 'LOW'
                END
            WHEN cm.cvss_v2_score IS NOT NULL AND cm.cvss_v2_score != -1 THEN
                CASE
                    WHEN cm.cvss_v2_score >= 7.0 THEN 'HIGH'
                    WHEN cm.cvss_v2_score >= 4.0 THEN 'MEDIUM'
                    WHEN cm.cvss_v2_score > 0.0 THEN 'LOW'
                END
            ELSE 'N/A'
        END AS severity_level,
        cm.cwe_ids,
        e.type as exploit_type,
        e.platform as exploit_platform,
        e.verified as exploit_verified,
        SUBSTR(cm.description, 1, 100) || '...' AS short_description
    FROM cve_main cm
    JOIN exploits e ON cm.cve_id = e.cve_id
    JOIN msrc_patches mp ON cm.cve_id = mp.cve_id
    WHERE cm.state = 'PUBLISHED'
        AND cm.date_reserved IS NOT NULL
        AND e.date_published IS NOT NULL
        AND mp.initial_release_date IS NOT NULL
        AND cm.date_reserved <= CURRENT_DATE
        AND e.date_published <= CURRENT_DATE
        AND DATE_DIFF('day', cm.date_reserved, e.date_published) > 1000
)
SELECT
    cve_id,
    date_reserved,
    exploit_date,
    days_to_exploit,
    ROUND(cvss_score, 1) AS cvss_score,
    cvss_version,
    severity_level,
    cwe_ids,
    exploit_type,
    exploit_platform,
    CASE WHEN exploit_verified = 1 THEN 'Yes' ELSE 'No' END AS verified,
    short_description
FROM long_exploit_gaps
ORDER BY days_to_exploit DESC
LIMIT 20;
```
### **Ch5_Tab_5.3_CVEs with more than 1000 days between Patching and Exploitation Date(All vendors)**

* **Question Answered**: Which CVEs have extremely long gaps (>1000 days) between exploit publication and patch availability?

* **SQL Query**:
```sql
WITH long_patch_gaps AS (
    -- Microsoft patches
    SELECT 
        cm.cve_id,
        cm.date_reserved,
        e.date_published as exploit_date,
        mp.initial_release_date as patch_date,
        'Microsoft' as patch_vendor,
        mp.product_name,
        DATE_DIFF('day', e.date_published, mp.initial_release_date) AS patch_exploit_gap,
        -- Prioritize CVSS versions: v4 -> v3 -> v2
        COALESCE(
            CASE WHEN cm.cvss_v4_score IS NOT NULL AND cm.cvss_v4_score != -1 THEN cm.cvss_v4_score END,
            CASE WHEN cm.cvss_v3_score IS NOT NULL AND cm.cvss_v3_score != -1 THEN cm.cvss_v3_score END,
            CASE WHEN cm.cvss_v2_score IS NOT NULL AND cm.cvss_v2_score != -1 THEN cm.cvss_v2_score END
        ) AS cvss_score,
        CASE 
            WHEN cm.cvss_v4_score IS NOT NULL AND cm.cvss_v4_score != -1 THEN 'v4'
            WHEN cm.cvss_v3_score IS NOT NULL AND cm.cvss_v3_score != -1 THEN 'v3'
            WHEN cm.cvss_v2_score IS NOT NULL AND cm.cvss_v2_score != -1 THEN 'v2'
            ELSE 'N/A'
        END AS cvss_version,
        CASE 
            WHEN cm.cvss_v4_score IS NOT NULL AND cm.cvss_v4_score != -1 THEN
                CASE 
                    WHEN cm.cvss_v4_score >= 9.0 THEN 'CRITICAL'
                    WHEN cm.cvss_v4_score >= 7.0 THEN 'HIGH'
                    WHEN cm.cvss_v4_score >= 4.0 THEN 'MEDIUM'
                    WHEN cm.cvss_v4_score > 0.0 THEN 'LOW'
                END
            WHEN cm.cvss_v3_score IS NOT NULL AND cm.cvss_v3_score != -1 THEN
                CASE 
                    WHEN cm.cvss_v3_score >= 9.0 THEN 'CRITICAL'
                    WHEN cm.cvss_v3_score >= 7.0 THEN 'HIGH'
                    WHEN cm.cvss_v3_score >= 4.0 THEN 'MEDIUM'
                    WHEN cm.cvss_v3_score > 0.0 THEN 'LOW'
                END
            WHEN cm.cvss_v2_score IS NOT NULL AND cm.cvss_v2_score != -1 THEN
                CASE 
                    WHEN cm.cvss_v2_score >= 7.0 THEN 'HIGH'
                    WHEN cm.cvss_v2_score >= 4.0 THEN 'MEDIUM'
                    WHEN cm.cvss_v2_score > 0.0 THEN 'LOW'
                END
            ELSE 'N/A'
        END AS severity_level,
        cm.cwe_ids,
        cm.description
    FROM cve_main cm
    JOIN exploits e ON cm.cve_id = e.cve_id
    JOIN msrc_patches mp ON cm.cve_id = mp.cve_id
    WHERE cm.state = 'PUBLISHED'
        AND cm.date_reserved IS NOT NULL
        AND e.date_published IS NOT NULL
        AND mp.initial_release_date IS NOT NULL
        AND mp.initial_release_date >= '2016-01-01'
        AND mp.initial_release_date <= '2025-05-13'
        AND e.date_published <= '2025-05-13'
        AND DATE_DIFF('day', e.date_published, mp.initial_release_date) > 1000
    
    UNION ALL
    
    -- RedHat patches
    SELECT 
        cm.cve_id,
        cm.date_reserved,
        e.date_published as exploit_date,
        rp.initial_release_date as patch_date,
        'RedHat' as patch_vendor,
        rp.product_name,
        DATE_DIFF('day', e.date_published, rp.initial_release_date) AS patch_exploit_gap,
        COALESCE(
            CASE WHEN cm.cvss_v4_score IS NOT NULL AND cm.cvss_v4_score != -1 THEN cm.cvss_v4_score END,
            CASE WHEN cm.cvss_v3_score IS NOT NULL AND cm.cvss_v3_score != -1 THEN cm.cvss_v3_score END,
            CASE WHEN cm.cvss_v2_score IS NOT NULL AND cm.cvss_v2_score != -1 THEN cm.cvss_v2_score END
        ) AS cvss_score,
        CASE 
            WHEN cm.cvss_v4_score IS NOT NULL AND cm.cvss_v4_score != -1 THEN 'v4'
            WHEN cm.cvss_v3_score IS NOT NULL AND cm.cvss_v3_score != -1 THEN 'v3'
            WHEN cm.cvss_v2_score IS NOT NULL AND cm.cvss_v2_score != -1 THEN 'v2'
            ELSE 'N/A'
        END AS cvss_version,
        CASE 
            WHEN cm.cvss_v4_score IS NOT NULL AND cm.cvss_v4_score != -1 THEN
                CASE 
                    WHEN cm.cvss_v4_score >= 9.0 THEN 'CRITICAL'
                    WHEN cm.cvss_v4_score >= 7.0 THEN 'HIGH'
                    WHEN cm.cvss_v4_score >= 4.0 THEN 'MEDIUM'
                    WHEN cm.cvss_v4_score > 0.0 THEN 'LOW'
                END
            WHEN cm.cvss_v3_score IS NOT NULL AND cm.cvss_v3_score != -1 THEN
                CASE 
                    WHEN cm.cvss_v3_score >= 9.0 THEN 'CRITICAL'
                    WHEN cm.cvss_v3_score >= 7.0 THEN 'HIGH'
                    WHEN cm.cvss_v3_score >= 4.0 THEN 'MEDIUM'
                    WHEN cm.cvss_v3_score > 0.0 THEN 'LOW'
                END
            WHEN cm.cvss_v2_score IS NOT NULL AND cm.cvss_v2_score != -1 THEN
                CASE 
                    WHEN cm.cvss_v2_score >= 7.0 THEN 'HIGH'
                    WHEN cm.cvss_v2_score >= 4.0 THEN 'MEDIUM'
                    WHEN cm.cvss_v2_score > 0.0 THEN 'LOW'
                END
            ELSE 'N/A'
        END AS severity_level,
        cm.cwe_ids,
        cm.description
    FROM cve_main cm
    JOIN exploits e ON cm.cve_id = e.cve_id
    JOIN redhat_patches rp ON cm.cve_id = rp.cve_id
    WHERE cm.state = 'PUBLISHED'
        AND cm.date_reserved IS NOT NULL
        AND e.date_published IS NOT NULL
        AND rp.initial_release_date IS NOT NULL
        AND rp.initial_release_date >= '2016-01-01'
        AND rp.initial_release_date <= '2025-05-13'
        AND e.date_published <= '2025-05-13'
        AND (LOWER(rp.product_name) LIKE '%rhel%' OR LOWER(rp.product_name) LIKE '%red hat%' OR LOWER(rp.product_name) LIKE '%enterprise linux%')
        AND DATE_DIFF('day', e.date_published, rp.initial_release_date) > 1000
    
    UNION ALL
    
    -- Cisco patches
    SELECT 
        cm.cve_id,
        cm.date_reserved,
        e.date_published as exploit_date,
        cp.initial_release_date as patch_date,
        'Cisco' as patch_vendor,
        cp.product_name,
        DATE_DIFF('day', e.date_published, cp.initial_release_date) AS patch_exploit_gap,
        COALESCE(
            CASE WHEN cm.cvss_v4_score IS NOT NULL AND cm.cvss_v4_score != -1 THEN cm.cvss_v4_score END,
            CASE WHEN cm.cvss_v3_score IS NOT NULL AND cm.cvss_v3_score != -1 THEN cm.cvss_v3_score END,
            CASE WHEN cm.cvss_v2_score IS NOT NULL AND cm.cvss_v2_score != -1 THEN cm.cvss_v2_score END
        ) AS cvss_score,
        CASE 
            WHEN cm.cvss_v4_score IS NOT NULL AND cm.cvss_v4_score != -1 THEN 'v4'
            WHEN cm.cvss_v3_score IS NOT NULL AND cm.cvss_v3_score != -1 THEN 'v3'
            WHEN cm.cvss_v2_score IS NOT NULL AND cm.cvss_v2_score != -1 THEN 'v2'
            ELSE 'N/A'
        END AS cvss_version,
        CASE 
            WHEN cm.cvss_v4_score IS NOT NULL AND cm.cvss_v4_score != -1 THEN
                CASE 
                    WHEN cm.cvss_v4_score >= 9.0 THEN 'CRITICAL'
                    WHEN cm.cvss_v4_score >= 7.0 THEN 'HIGH'
                    WHEN cm.cvss_v4_score >= 4.0 THEN 'MEDIUM'
                    WHEN cm.cvss_v4_score > 0.0 THEN 'LOW'
                END
            WHEN cm.cvss_v3_score IS NOT NULL AND cm.cvss_v3_score != -1 THEN
                CASE 
                    WHEN cm.cvss_v3_score >= 9.0 THEN 'CRITICAL'
                    WHEN cm.cvss_v3_score >= 7.0 THEN 'HIGH'
                    WHEN cm.cvss_v3_score >= 4.0 THEN 'MEDIUM'
                    WHEN cm.cvss_v3_score > 0.0 THEN 'LOW'
                END
            WHEN cm.cvss_v2_score IS NOT NULL AND cm.cvss_v2_score != -1 THEN
                CASE 
                    WHEN cm.cvss_v2_score >= 7.0 THEN 'HIGH'
                    WHEN cm.cvss_v2_score >= 4.0 THEN 'MEDIUM'
                    WHEN cm.cvss_v2_score > 0.0 THEN 'LOW'
                END
            ELSE 'N/A'
        END AS severity_level,
        cm.cwe_ids,
        cm.description
    FROM cve_main cm
    JOIN exploits e ON cm.cve_id = e.cve_id
    JOIN cisco_patches cp ON cm.cve_id = cp.cve_id
    WHERE cm.state = 'PUBLISHED'
        AND cm.date_reserved IS NOT NULL
        AND e.date_published IS NOT NULL
        AND cp.initial_release_date IS NOT NULL
        AND cp.initial_release_date >= '2016-01-01'
        AND cp.initial_release_date <= '2025-05-13'
        AND e.date_published <= '2025-05-13'
        AND DATE_DIFF('day', e.date_published, cp.initial_release_date) > 1000
)
SELECT 
    cve_id,
    date_reserved,
    exploit_date,
    patch_date,
    patch_exploit_gap,
    patch_vendor,
    product_name,
    ROUND(cvss_score, 1) as cvss_score,
    cvss_version,
    severity_level,
    cwe_ids,
    SUBSTR(description, 1, 100) || '...' AS short_description
FROM long_patch_gaps
ORDER BY patch_exploit_gap DESC
LIMIT 20;
```

# **Comparative Analysis of Patching and Vulnerability Lifecycles: Commercial Vendors vs. Open Source**

This document provides SQL queries (DuckDB syntax) and Apache Superset configurations for a comparative analysis of patching and vulnerability lifecycle events across major commercial vendors (Microsoft, Red Hat, Cisco) and prominent open-source ecosystems (GitHub Advisories, MoreFixes). The analysis incorporates data up to May 13, 2025, and adheres to the specific filtering requirements for Red Hat products and the distinctions between commercial and open-source patch data.

## **Unified Patch Data Definition**

To facilitate comprehensive comparisons, the following Common Table Expression (CTE) named unified_patches combines patch information from all available sources, standardizing column names and introducing a vendor_source and patch_type to distinguish between commercial vendors and open-source projects. This CTE will be used as the foundation for subsequent queries.

```sql
WITH unified_patches AS (  
    -- Microsoft Patches  
    SELECT  
        cve_id,  
        release_date AS patch_date,  
        'Microsoft' AS vendor_source,  
        'Commercial' AS patch_type,  
        cvss_score,  
        cvss_vector,  
        cwe_ids  
    FROM  
        msrc_patches  
    WHERE  
        release_date <= '2025-05-13'

    UNION ALL

    -- Red Hat Patches (filtered for official Red Hat products)  
    SELECT  
        cve_id,  
        current_release_date AS patch_date,  
        'RedHat' AS vendor_source,  
        'Commercial' AS patch_type,  
        cvss_score,  
        cvss_vector,  
        cwe_id AS cwe_ids -- Assuming cwe_id is singular in redhat_patches  
    FROM  
        redhat_patches  
    WHERE  
        current_release_date <= '2025-05-13'  
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
        current_release_date AS patch_date,  
        'Cisco' AS vendor_source,  
        'Commercial' AS patch_type,  
        cvss_score,  
        cvss_vector,  
        NULL AS cwe_ids -- Cisco patches table doesn't have cwe_ids directly  
    FROM  
        cisco_patches  
    WHERE  
        current_release_date <= '2025-05-13'

    UNION ALL

    -- GitHub Advisories (inferred patches)  
    SELECT  
        primary_cve AS cve_id,  
        published AS patch_date, -- Using published date as patch date for advisories  
        'GitHub' AS vendor_source,  
        'OpenSource' AS patch_type,  
        cvss_v3_score AS cvss_score,  
        cvss_v3_vector AS cvss_v3_vector,  
        cwe_ids  
    FROM  
        github_advisories  
    WHERE  
        (patched = 1 OR patch_available = 1)  
        AND published <= '2025-05-13'  
        AND primary_cve IS NOT NULL AND primary_cve != ''

    UNION ALL

    -- MoreFixes (commits as fixes)  
    SELECT  
        mf_f.cve_id,  
        mf_c.author_date AS patch_date,  
        'MoreFixes' AS vendor_source,  
        'OpenSource' AS patch_type,  
        NULL AS cvss_score, -- MoreFixes fixes table doesn't have CVSS directly  
        NULL AS cvss_vector,  
        mf_cw.cwe_id AS cwe_ids -- Join with morefixes_cwe_classification for CWEs  
    FROM  
        morefixes_fixes AS mf_f  
    JOIN  
        morefixes_commits AS mf_c ON mf_f.hash = mf_c.hash  
    LEFT JOIN  
        morefixes_cwe_classification AS mf_cw ON mf_f.cve_id = mf_cw.cve_id  
    WHERE  
        mf_c.author_date <= '2025-05-13'  
        AND mf_f.cve_id IS NOT NULL AND mf_f.cve_id != ''  
)
```

## **Patching Volume by Vendor/Source**

* **Question Answered**: How has the volume of patches changed annually across commercial vendors and open-source projects?  
* **SQL Query**:  
```sql
  -- Requires the unified_patches CTE defined above  
  WITH unified_patches AS (  
      -- ... (Unified Patch Data CTE as defined in the introduction) ...  
  )  
  SELECT  
      STRFTIME(patch_date, '%Y') AS year,  
      vendor_source,  
      COUNT(DISTINCT cve_id) AS patched_cve_count  
  FROM  
      unified_patches  
  WHERE  
      patch_date >= '2016-01-01' -- Start from a reasonable comparison point  
  GROUP BY  
      year, vendor_source  
  ORDER BY  
      year, vendor_source;
```
* **Superset Chart Type**: Line Chart  
* **Superset Configuration**:  
  * **X-axis**: year  
  * **Y-axis**: patched_cve_count  
  * **Group By**: vendor_source  
  * **Time Range**: Custom, e.g., 2016-01-01 to 2025-05-13  
  * **Chart Options**: Use different colors for each vendor_source.

## **Top Patched CWEs by Vendor/Source**

* **Question Answered**: What are the most common weakness types addressed by patches from different commercial vendors and open-source projects?  
* **SQL Query**: (This query will show top CWEs for each vendor/source. You might need to create separate charts in Superset or use a filter for vendor_source.)  
```sql
  -- Requires the unified_patches CTE defined above  
  WITH unified_patches AS (  
      -- ... (Unified Patch Data CTE as defined in the introduction) ...  
  ),  
  PatchedCWEs AS (  
      SELECT  
          up.vendor_source,  
          t.cwe_id,  
          COUNT(DISTINCT up.cve_id) AS patched_cve_count  
      FROM  
          unified_patches AS up  
      CROSS JOIN UNNEST(STRING_SPLIT_BY_REGEX(up.cwe_ids, ',')) AS t(cwe_id)  
      WHERE  
          t.cwe_id IS NOT NULL AND t.cwe_id != ''  
          AND up.patch_date <= '2025-05-13'  
      GROUP BY  
          up.vendor_source, t.cwe_id  
  )  
  SELECT  
      pc.vendor_source,  
      cr.name AS cwe_name,  
      pc.patched_cve_count  
  FROM  
      PatchedCWEs AS pc  
  LEFT JOIN  
      cwe_ref AS cr ON pc.cwe_id = cr.cwe_id  
  QUALIFY ROW_NUMBER() OVER (PARTITION BY pc.vendor_source ORDER BY pc.patched_cve_count DESC) <= 10  
  ORDER BY  
      pc.vendor_source, pc.patched_cve_count DESC;
```
* **Superset Chart Type**: Bar Chart (Horizontal)  
* **Superset Configuration**:  
  * **X-axis**: patched_cve_count  
  * **Y-axis**: cwe_name  
  * **Breakdown by**: vendor_source (This will create separate bars for each vendor/source, allowing comparison)  
  * **Sort By**: patched_cve_count (Descending)  
  * **Limit**: 10 (per vendor/source, handled by QUALIFY in SQL)

## **Time to Patch by Severity (Multi-Vendor/Source)**

* **Question Answered**: How does time to patch vary by severity across different commercial vendors and open-source projects?  
* **SQL Query**: (This query joins with cve_main to get severity and date_published for Time to Patch calculation. It uses cvss_v3_severity.)  
```sql
  -- Requires the unified_patches CTE defined above  
  WITH unified_patches AS (  
      -- ... (Unified Patch Data CTE as defined in the introduction) ...  
  )  
  SELECT  
      up.vendor_source,  
      cm.cvss_v3_severity AS severity_level,  
      MEDIAN(DATEDIFF('day', cm.date_published, up.patch_date)) AS median_days_to_patch  
  FROM  
      unified_patches AS up  
  JOIN  
      cve_main AS cm ON up.cve_id = cm.cve_id  
  WHERE  
      cm.cvss_v3_severity IS NOT NULL AND cm.cvss_v3_severity != ''  
      AND cm.cvss_v3_severity IN ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW') -- Filter valid severities  
      AND cm.date_published IS NOT NULL  
      AND up.patch_date IS NOT NULL  
      AND up.patch_date >= '2016-01-01' -- Align with patch data start  
      AND up.patch_date <= '2025-05-13'  
  GROUP BY  
      up.vendor_source, severity_level  
  ORDER BY  
      up.vendor_source,  
      CASE cm.cvss_v3_severity  
          WHEN 'CRITICAL' THEN 1  
          WHEN 'HIGH' THEN 2  
          WHEN 'MEDIUM' THEN 3  
          WHEN 'LOW' THEN 4  
          ELSE 5  
      END;
```
* **Superset Chart Type**: Grouped Bar Chart  
* **Superset Configuration**:  
  * **X-axis**: severity_level  
  * **Y-axis**: median_days_to_patch  
  * **Group By**: vendor_source  
  * **Sort By**: Custom order for severity (Critical, High, Medium, Low)

## **Exploit-Patch Gap (Multi-Vendor/Source)**

* **Question Answered**: What is the typical time gap between exploit publication and patch availability for different vendors and open-source projects?  
* **SQL Query**: (This query considers CVEs that have both an exploit and a patch. It uses the earliest exploit date from exploits table.)  
```sql
  -- Requires the unified_patches CTE defined above  
  WITH unified_patches AS (  
      -- ... (Unified Patch Data CTE as defined in the introduction) ...  
  )  
  SELECT  
      up.vendor_source,  
      MEDIAN(DATEDIFF('day', e.date_published, up.patch_date)) AS median_exploit_patch_gap  
  FROM  
      unified_patches AS up  
  JOIN  
      exploits AS e ON up.cve_id = e.cve_id  
  WHERE  
      e.date_published IS NOT NULL  
      AND up.patch_date IS NOT NULL  
      AND up.patch_date >= '2016-01-01' -- Align with patch data start  
      AND up.patch_date <= '2025-05-13'  
  GROUP BY  
      up.vendor_source  
  ORDER BY  
      median_exploit_patch_gap;
```
* **Superset Chart Type**: Bar Chart  
* **Superset Configuration**:  
  * **X-axis**: vendor_source  
  * **Y-axis**: median_exploit_patch_gap  
  * **Sort By**: median_exploit_patch_gap (Ascending)  
  * **Chart Options**: Consider adding a reference line at 0 to clearly show positive/negative gaps.

## **Exploited vs. Non-Exploited Patching Time (Multi-Vendor/Source)**

* **Question Answered**: How does the time to patch differ for exploited versus non-exploited vulnerabilities across different vendors and open-source projects?  
* **SQL Query**: (This query joins unified_patches with cve_main to get has_exploit status and date_published for Time to Patch calculation.)  
```sql
  -- Requires the unified_patches CTE defined above  
  WITH unified_patches AS (  
      -- ... (Unified Patch Data CTE as defined in the introduction) ...  
  )  
  SELECT  
      up.vendor_source,  
      CASE  
          WHEN cm.has_exploit = 1 THEN 'Exploited'  
          ELSE 'Non-Exploited'  
      END AS exploitation_status,  
      MEDIAN(DATEDIFF('day', cm.date_published, up.patch_date)) AS median_days_to_patch  
  FROM  
      unified_patches AS up  
  JOIN  
      cve_main AS cm ON up.cve_id = cm.cve_id  
  WHERE  
      cm.date_published IS NOT NULL  
      AND up.patch_date IS NOT NULL  
      AND up.patch_date >= '2016-01-01' -- Align with patch data start  
      AND up.patch_date <= '2025-05-13'  
  GROUP BY  
      up.vendor_source, exploitation_status  
  ORDER BY  
      up.vendor_source, exploitation_status;
```
* **Superset Chart Type**: Grouped Bar Chart  
* **Superset Configuration**:  
  * **X-axis**: vendor_source  
  * **Y-axis**: median_days_to_patch  
  * **Group By**: exploitation_status  
  * **Sort By**: vendor_source