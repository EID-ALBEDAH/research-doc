# Data Dictionary and Schema Overview for Security Vulnerability Datasets

This documentation describes the schema, sources, and column definitions for all tables in the unified vulnerability database. The goal is to support data analysts in exploring and interpreting complex security datasets. All tables are loaded into a DuckDB database (~25GB) and sourced from trusted industry feeds like NVD, MITRE, Microsoft, RedHat, GitHub, CISA, ExploitDB, and MoreFixes.

---

## Table: `cve_main`

**Source**: MITRE CVE-V5, NVD, CISA KEV, CISA SSVC, ExploitDB

| Column                   | Description                                  |
| ------------------------ | -------------------------------------------- |
| id                       | Internal unique identifier                   |
| cve_id                  | CVE ID from MITRE/NVD                        |
| assigner_org            | Organization that assigned the CVE           |
| state                    | CVE state: PUBLISHED or REJECTED             |
| description              | CVE description text                         |
| date_reserved           | When the CVE ID was reserved                 |
| date_published          | When the CVE was published                   |
| date_updated            | Last update timestamp                        |
| cvss_v2_score          | CVSS v2 score (0.0–10.0)                     |
| cvss_v2_vector         | Vector string for CVSS v2                    |
| cvss_v3_score          | CVSS v3 score                                |
| cvss_v3_vector         | CVSS v3 vector                               |
| cvss_v3_severity       | Severity level (LOW, MEDIUM, HIGH, CRITICAL) |
| cvss_v4_score          | CVSS v4 score                                |
| cvss_v4_vector         | CVSS v4 vector string                        |
| cvss_v4_severity       | CVSS v4 severity classification              |
| cwe_ids                 | Comma-separated list of CWE IDs              |
| cpes                     | Comma-separated CPEs affected                |
| vendors                  | Vendors (can be imprecise)                   |
| products                 | Products (can be imprecise)                  |
| references               | List of external references (URLs)           |
| ssvc_exploitation       | SSVC status: "active", "poc", or "none"      |
| ssvc_automatable        | Is the issue automatable?                    |
| ssvc_technical_impact  | Level of technical impact                    |
| kev_known_exploited    | 1 if listed in CISA KEV                      |
| kev_vendor_project     | Vendor/project name from KEV                 |
| kev_product             | Product name from KEV                        |
| kev_vulnerability_name | Title from CISA KEV advisory                 |
| kev_date_added         | Date added to KEV list                       |
| kev_short_description  | Short description from KEV                   |
| kev_required_action    | Recommended mitigation action                |
| kev_due_date           | Deadline for remediation                     |
| kev_ransomware_use     | Indicates ransomware involvement             |
| kev_notes               | Any notes from KEV advisory                  |
| kev_cwes                | Associated CWE(s) in KEV                     |
| epss_score              | EPSS likelihood score (0-1)                  |
| epss_percentile         | EPSS global percentile                       |
| data_sources            | Comma-separated source indicators            |
| created_at              | DB timestamp (ignore)                        |
| updated_at              | DB timestamp (ignore)                        |
| has_exploit             | 1 if exploit exists in ExploitDB             |
| exploit_count           | Number of exploits in ExploitDB for this CVE |
| first_exploit_date     | Earliest exploit date (ignore)               |
| latest_exploit_date    | Latest exploit date (ignore)                 |

---

## Table: `exploits`

**Source**: ExploitDB

| Column           | Description                             |
| ---------------- | --------------------------------------- |
| id               | Internal ID                             |
| file             | File name or path to exploit code       |
| description      | Description of the exploit              |
| date_published  | Date of publication in ExploitDB        |
| author           | Author of the exploit                   |
| type             | Exploit type (e.g., local, remote)      |
| platform         | Affected platform                       |
| port             | Port used by exploit if applicable      |
| date_added      | When added to DB                        |
| date_updated    | Last update to record                   |
| verified         | 1 if exploit was verified               |
| codes            | Exploit code or snippets                |
| tags             | Tags (e.g., webapps, dos)               |
| aliases          | Alternative exploit names or IDs        |
| screenshot_url  | Screenshot of exploit demo if available |
| application_url | URL of affected application             |
| source_url      | Source reference                        |
| cve_id          | Related CVE ID                          |

---

## Table: `msrc_patches`

**Source**: Microsoft MSRC (CVRF/CSAF)

| Column                       | Description                                       |
| ---------------------------- | ------------------------------------------------- |
| title                        | Title of the advisory                             |
| release_date                | Official patch release date                       |
| initial_release_date       | Initial release of the advisory                   |
| cvrf_id                     | Microsoft advisory ID                             |
| cve_id                      | CVE associated                                    |
| exploited_status            | 1 if exploited                                    |
| exploitation_potential_lsr | Exploitation potential - Latest security release  |
| exploitation_potential_osr | Exploitation potential - Other supported releases |
| publicly_disclosed          | 1 if publicly disclosed                           |
| cvss_score                  | CVSS score                                        |
| cvss_vector                 | Vector string                                     |
| vuln_title                  | Title of the vulnerability                        |
| product_id                  | Internal product ID                               |
| product_name                | Human-readable product name                       |
| product_branch              | Specific version or release branch                |
| product_cpe                 | CPE name for affected software                    |
| threats                      | Known threats or risks                            |
| remediations                 | Mitigations or patch steps                        |
| cwe_ids                     | Comma-separated CWE list                          |
| notes                        | Notes from Microsoft                              |
| acknowledgments              | Credit for discovery                              |

*Records follow CVE–Product pairs. A single advisory may appear multiple times.*

---

## Table: `redhat_patches`

**Source**: Red Hat Security Advisory (CSAF)

| Column                 | Description                                          |
| ---------------------- | ---------------------------------------------------- |
| id                     | Internal ID                                          |
| advisory_id           | Red Hat Advisory ID                                  |
| title                  | Title of advisory                                    |
| cve_id                | CVE associated                                       |
| cwe_id                | CWE ID                                               |
| vulnerability_title   | Vulnerability title                                  |
| current_release_date | Current release date                                 |
| initial_release_date | First release date                                   |
| discovery_date        | When discovered                                      |
| release_date          | Full release timeline                                |
| status                 | Advisory status                                      |
| version                | Package version patched                              |
| publisher              | "Red Hat" or other originator                        |
| publisher_category    | Type of publisher (vendor, third-party, etc.)        |
| summary                | Summary of advisory                                  |
| details                | Detailed description                                 |
| cvss_score            | CVSS score                                           |
| cvss_severity         | Severity rating (LOW–CRITICAL)                       |
| cvss_vector           | Vector string                                        |
| threat_impact         | Description of impact                                |
| aggregate_severity    | Aggregated severity level                            |
| product_id            | Product ID (e.g. "3AS:openmotif-debuginfo-0:2.2.3") |
| product_name          | Product name (e.g. "Red Hat Linux 7.1")              |

**Note**: RedHat includes open source and third-party projects. To filter for official RedHat products, use these keywords in `product_name` or `product_id`: `rh, red hat, red-hat, rhel, enterprise linux, baseos, appstream, openshift`

---

## Table: `cisco_patches`

**Source**: Cisco PSIRT (CSAF)

| Column                       | Description                          |
| ---------------------------- | ------------------------------------ |
| advisory_id                 | Cisco Advisory ID                    |
| title                        | Title of advisory                    |
| cve_id                      | CVE associated                       |
| vulnerability_title         | Vulnerability title                  |
| current_release_date       | Latest version date                  |
| initial_release_date       | First published                      |
| vulnerability_release_date | Actual vulnerability disclosure date |
| status                       | Advisory status                      |
| version                      | Advisory version                     |
| publisher                    | Cisco or partner                     |
| publisher_category          | Type of publisher                    |
| summary                      | Summary text                         |
| details                      | Detailed description                 |
| cvss_score                  | CVSS score                           |
| cvss_severity               | Severity label                       |
| cvss_vector                 | Vector string                        |
| bug_ids                     | Related bug trackers                 |
| product_id                  | Cisco product ID                     |
| product_name                | Human-readable product name          |
| product_full_path          | Full internal path to product        |
| acknowledgments              | Credits                              |
| references                   | External URLs                        |
| remediations                 | Steps to fix                         |

---

## Table: `github_advisories`

**Source**: GitHub Advisory Database

| Column                | Description                                           |
| --------------------- | ----------------------------------------------------- |
| id                    | Internal ID                                           |
| ghsa_id              | GitHub Security Advisory ID (GHSA-...)                |
| schema_version       | Version of advisory schema                            |
| published             | Publish timestamp                                     |
| modified              | Last modification timestamp                           |
| summary               | One-line summary                                      |
| details               | Full description                                      |
| primary_cve          | Main CVE ID                                           |
| all_cves             | All related CVEs                                      |
| cvss_v3_score       | CVSS v3 score                                         |
| cvss_v3_vector      | CVSS v3 vector                                        |
| cvss_v4_score       | CVSS v4 score                                         |
| cvss_v4_vector      | CVSS v4 vector                                        |
| database_severity    | Severity category (GitHub-defined)                    |
| severity_score       | Internal numeric score                                |
| cwe_ids              | CWE IDs                                               |
| github_reviewed      | Boolean if reviewed by GitHub                         |
| github_reviewed_at  | Timestamp of review                                   |
| nvd_published_at    | When added to NVD                                     |
| exploited             | 1 if exploitation confirmed **(inferred)**            |
| exploitability_level | 0–3 scale based on inferred difficulty                |
| poc_available        | 1 if PoC or exploit publicly available **(inferred)** |
| patched               | 1 if patched **(inferred)**                           |
| patch_available      | 1 if patch reference is present **(inferred)**        |
| primary_ecosystem    | Ecosystem (e.g., npm, pip)                            |
| all_ecosystems       | All affected ecosystems                               |
| package_ecosystem    | Package ecosystem (npm, pip, etc.)                    |
| package_name         | Name of affected package                              |
| package_purl         | Package URL identifier (PURL)                         |
| references            | List of references (URLs)                             |
| affected_ranges      | Version range strings affected                        |
| affected_versions    | Specific affected versions                            |

**Note on Inferred Columns (added by ETL)**:
These columns are not native to GitHub but derived using keyword scanning:

- `exploited`: Based on terms like "actively exploited", "attacks observed"
- `poc_available`: Based on PoC keywords or references to known exploit databases (e.g., ExploitDB)
- `exploitability_level`: 0–3 scale based on terms like "trivial to exploit", "complex exploitation"
- `patched`, `patch_available`: Extracted from JSON `affected.ranges.events` if "fixed" or patch reference is present

---

## Table: `cwe_ref`

**Source**: MITRE CWE

### Full Table: `cwe_ref`

**Source**: MITRE CWE

| Column                    | Description                                                        |
| ------------------------- | ------------------------------------------------------------------ |
| cwe_id                   | Unique identifier for the CWE entry (e.g., CWE-79)                 |
| name                      | Short title of the weakness (e.g., Cross-site Scripting)           |
| weakness_abstraction     | Generalization level: Base, Variant, Class, etc.                   |
| status                    | Current status: Draft, Incomplete, Deprecated, etc.                |
| description               | Brief description of the weakness                                  |
| extended_description     | Full textual explanation including implications, context, examples |
| related_weaknesses       | List of associated or parent/child CWE IDs                         |
| weakness_ordinalities    | Ordering of weakness by nature or relevance                        |
| applicable_platforms     | Technology platforms (e.g., Web, IoT, Mobile)                      |
| background_details       | Additional background for understanding                            |
| alternate_terms          | Other names or aliases for this weakness                           |
| modes_of_introduction   | How the weakness typically arises in development                   |
| exploitation_factors     | Factors affecting how this weakness can be exploited               |
| likelihood_of_exploit   | Qualitative probability of exploitation (e.g., High, Medium)       |
| common_consequences      | Typical impacts such as DoS, Data Disclosure                       |
| detection_methods        | How the weakness is typically detected (e.g., SAST)                |
| potential_mitigations    | Recommended mitigation techniques                                  |
| observed_examples        | CVE examples linked to this weakness                               |
| functional_areas         | Functional areas affected, such as Authentication                  |
| affected_resources       | System elements affected (e.g., Database, Web Layer)               |
| taxonomy_mappings        | Linked taxonomies such as OWASP Top 10                             |
| related_attack_patterns | CAPEC IDs related to the weakness                                  |
| notes                     | Editorial or historical notes                                      |
| created_at               | Timestamp of record creation                                       |

#### Example Row:

| cwe_id | name                             | weakness_abstraction | status   | description                                                                                                                                                                                                                               |
| ------- | -------------------------------- | --------------------- | -------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| CWE-79  | Improper Neutralization of Input | Variant               | Complete | The software does not neutralize or incorrectly neutralizes user-controllable input before it is placed in output that is used as a web page that is served to other users. This allows attackers to inject arbitrary web script or HTML. |

---

## Table: `capec_ref`

**Source**: MITRE CAPEC

### Full Table: `capec_ref`

**Source**: MITRE CAPEC

| Column                    | Description                                                                                 |
| ------------------------- | ------------------------------------------------------------------------------------------- |
| capec_id                 | Unique CAPEC identifier (e.g., CAPEC-1)                                                     |
| name                      | Name of the attack pattern (e.g., Accessing Functionality Not Properly Constrained by ACLs) |
| abstraction               | Abstraction level (Standard, Meta, etc.)                                                    |
| status                    | Entry status (e.g., Draft, Complete)                                                        |
| description               | Brief description of the attack pattern                                                     |
| alternate_terms          | Other terms used for the same pattern                                                       |
| likelihood_of_attack    | Qualitative assessment (e.g., High, Medium)                                                 |
| typical_severity         | Expected severity if the attack is successful (e.g., High)                                  |
| related_attack_patterns | List of CAPEC relationships (e.g., ChildOf, CanPrecede)                                     |
| execution_flow           | Sequence of actions for attack execution                                                    |
| prerequisites             | Conditions required for the attack to succeed                                               |
| skills_required          | Skill level necessary for an attacker                                                       |
| resources_required       | Tools or resources an attacker needs                                                        |
| indicators                | Observable signs of this attack pattern                                                     |
| consequences              | Potential impacts on confidentiality, integrity, availability                               |
| mitigations               | Recommendations to prevent or mitigate the attack                                           |
| example_instances        | Known real-world examples of this pattern                                                   |
| related_weaknesses       | CWE IDs related to this CAPEC pattern                                                       |
| taxonomy_mappings        | External taxonomy associations (e.g., ATT&CK)                                               |
| notes                     | Editorial, contextual, or historical notes                                                  |
| created_at               | Timestamp of record creation                                                                |

#### Example Row:

| capec_id | name                                                     | abstraction | status | description                                                                                                                                                                |
| --------- | -------------------------------------------------------- | ----------- | ------ | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| CAPEC-1   | Accessing Functionality Not Properly Constrained by ACLs | Standard    | Draft  | Attackers access web functionality not protected by ACLs due to misconfiguration or missing access control. This can lead to privilege escalation or unauthorized actions. |

---

## Table Family: `morefixes_*`

**Source**: MoreFixes Dataset (JafarAkhondali et al., 2024)
Paper: [https://dl.acm.org/doi/abs/10.1145/3663533.3664036](https://dl.acm.org/doi/abs/10.1145/3663533.3664036)
Repo: [https://github.com/JafarAkhondali/Morefixes](https://github.com/JafarAkhondali/Morefixes)

See full data dictionary in the official repository or appendix of the paper.



---

## Full Table Family: `morefixes_*`

Below are summaries of the main MoreFixes tables with example data for each.

### Table: `morefixes_cve`

| Column                      | Description                   |
| --------------------------- | ----------------------------- |
| cve_id                     | CVE ID                        |
| published_date             | CVE publication date          |
| last_modified_date        | Last modified date            |
| description                 | CVE summary                   |
| nodes                       | Affected OS/software versions |
| severity                    | Severity level                |
| obtain_all_privilege      | Boolean flag                  |
| obtain_user_privilege     | Boolean flag                  |
| obtain_other_privilege    | Boolean flag                  |
| user_interaction_required | Boolean flag                  |
| cvss2_vector_string       | CVSSv2 vector string          |
| cvss3_vector_string       | CVSSv3 vector string          |

**Example**:
| CVE-2021-1234 | 2021-03-05 | 2021-06-01 | Buffer overflow in X | Linux 5.10 | HIGH | FALSE | TRUE | FALSE | TRUE | AV:N/AC:L/Au:N/C:P/I:P/A:P | AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H |

---

### Table: `morefixes_fixes`

| Column    | Description                           |
| --------- | ------------------------------------- |
| cve_id   | CVE ID                                |
| hash      | Commit hash                           |
| repo_url | Git repository URL                    |
| rel_type | Commit relation type                  |
| score     | Score based on relevance (e.g., 1337) |

**Example**:
| CVE-2021-1234 | abcdef123456 | [https://github.com/example/repo](https://github.com/example/repo) | direct | 1337 |

---

### Table: `morefixes_commits`

| Column              | Description    |
| ------------------- | -------------- |
| hash                | Commit hash    |
| repo_url           | Repository URL |
| author              | Author name    |
| msg                 | Commit message |
| num_lines_added   | Lines added    |
| num_lines_deleted | Lines deleted  |
| author_date        | Timestamp      |

**Example**:
| abcdef123456 | [https://github.com/example/repo](https://github.com/example/repo) | dev123 | Fix buffer overflow | 34 | 12 | 2021-03-06T10:22:11+00:00 |

---

### Table: `morefixes_repository`

| Column           | Description       |
| ---------------- | ----------------- |
| repo_url        | Repository URL    |
| repo_name       | Name of repo      |
| description      | Short description |
| date_created    | When repo created |
| date_last_push | When last pushed  |
| owner            | Owner username    |

**Example**:
| [https://github.com/example/repo](https://github.com/example/repo) | example/repo | A demo project | 2019-01-01 | 2023-07-01 | dev123 |

---

### Table: `morefixes_file_change`

| Column           | Description             |
| ---------------- | ----------------------- |
| file_change_id | Unique ID               |
| hash             | Commit hash             |
| filename         | File name               |
| change_type     | ADD/DELETE/MODIFY       |
| diff             | Git diff                |
| code_before     | Code snippet before fix |
| code_after      | Code snippet after fix  |

**Example**:
| fc123 | abcdef123456 | main.c | MODIFY | ...diff... | vulnerable_func() | fixed_func() |

---

### Table: `morefixes_method_change`

| Column             | Description           |
| ------------------ | --------------------- |
| method_change_id | Unique ID             |
| file_change_id   | FK to file change     |
| name               | Function/method name  |
| code               | Full method code      |
| complexity         | Cyclomatic complexity |

**Example**:
| mc456 | fc123 | checkAuth | void checkAuth() { ... } | 4 |

---

### Table: `morefixes_cwe_classification`

| Column  | Description |
| ------- | ----------- |
| cve_id | CVE ID      |
| cwe_id | CWE ID      |

**Example**:
| CVE-2021-1234 | CWE-787 |

---

### Table: `morefixes_cwe`

| Column       | Description       |
| ------------ | ----------------- |
| cwe_id      | CWE ID            |
| cwe_name    | Name of weakness  |
| description  | Short description |
| is_category | Boolean           |

**Example**:
| CWE-787 | Out-of-bounds Write | Writing outside buffer | FALSE |

---


## Additional Notes

- **CVSS and EPSS Scoring**: If any `cvss_*_score` or `epss_score`/`epss_percentile` value is `-1`, this indicates that the score was not available from the source.
- **Exploitation Temporal Data**: The only temporal data associated with exploitation is found in the `exploit` table from ExploitDB (i.e., `date_published`). All other datasets lack explicit timestamps for when exploitation was observed or occurred.
- **`kev_date_added`**** Column**: In `cve_main`, this field reflects the date when CISA became aware of the exploit—not necessarily when the exploitation began.
- **RedHat Product Filtering**: To ensure only official Red Hat products are selected from `redhat_patches`, filter using keywords like: `rh, red hat, red-hat, rhel, enterprise linux, baseos, appstream, openshift` in either `product_name` or `product_id`.
- **GitHub Advisory Enhancements**: Fields such as `exploited`, `poc_available`, `exploitability_level`, and `patch_available` in `github_advisories` are not natively provided. They are inferred via keyword detection from text and URLs.
- **Duplication Notice**: CVE–product pairs may appear multiple times in `msrc_patches`, `redhat_patches`, and `github_advisories` due to one CVE affecting multiple packages or platforms.
- **Patch Dataset Comparison**: Patch information from `msrc_patches`, `cisco_patches`, and `redhat_patches` pertains to vendor-provided advisories. In contrast, patch information from `github_advisories`, `morefixes_*`, and third-party entries in `redhat_patches` relates to open source ecosystems (e.g., npm, PyPI). These should not be directly compared due to differences in context, format, and completeness.
