# 🛡️ MCP-Sentinel Security Audit Report

**Target:** `C:\Users\Ansh\go\bin\github-mcp-server.exe stdio --toolsets all`  
**Audit Timestamp:** 2026-09-19T10:36:30.041035+00:00  
**Security Health Score:** `44/100`  

## 📊 Summary Metrics

| Severity | Count |
|---|---|
| 🚨 Critical | **0** |
| 🔥 High | **0** |
| ⚠️ Medium | **0** |
| ℹ️ Low | **28** |
| Total Findings | **28** |

## 🔍 Detailed Vulnerabilities

### 1. [LOW] Unbounded Array Input on 'reviewers'

- **Tool Name:** `create_pull_request`
- **Parameter:** `reviewers`
- **Category:** Missing Parameter Boundary Validation
- **CWE:** CWE-400

**Description:**
Parameter 'reviewers' does not define 'maxItems'. Large payload arrays could trigger context window exhaustion or memory consumption.

**Remediation:**
> Specify 'maxItems' in the JSON Schema definition for array inputs.

---

### 2. [LOW] Unbounded Array Input on 'bypass_actors'

- **Tool Name:** `create_repository_ruleset`
- **Parameter:** `bypass_actors`
- **Category:** Missing Parameter Boundary Validation
- **CWE:** CWE-400

**Description:**
Parameter 'bypass_actors' does not define 'maxItems'. Large payload arrays could trigger context window exhaustion or memory consumption.

**Remediation:**
> Specify 'maxItems' in the JSON Schema definition for array inputs.

---

### 3. [LOW] Unbounded Array Input on 'rules'

- **Tool Name:** `create_repository_ruleset`
- **Parameter:** `rules`
- **Category:** Missing Parameter Boundary Validation
- **CWE:** CWE-400

**Description:**
Parameter 'rules' does not define 'maxItems'. Large payload arrays could trigger context window exhaustion or memory consumption.

**Remediation:**
> Specify 'maxItems' in the JSON Schema definition for array inputs.

---

### 4. [LOW] Unbounded Array Input on 'properties'

- **Tool Name:** `custom_properties_write`
- **Parameter:** `properties`
- **Category:** Missing Parameter Boundary Validation
- **CWE:** CWE-400

**Description:**
Parameter 'properties' does not define 'maxItems'. Large payload arrays could trigger context window exhaustion or memory consumption.

**Remediation:**
> Specify 'maxItems' in the JSON Schema definition for array inputs.

---

### 5. [LOW] Unbounded Array Input on 'fields'

- **Tool Name:** `get_file_contents`
- **Parameter:** `fields`
- **Category:** Missing Parameter Boundary Validation
- **CWE:** CWE-400

**Description:**
Parameter 'fields' does not define 'maxItems'. Large payload arrays could trigger context window exhaustion or memory consumption.

**Remediation:**
> Specify 'maxItems' in the JSON Schema definition for array inputs.

---

### 6. [LOW] Unbounded Array Input on 'assignees'

- **Tool Name:** `issue_write`
- **Parameter:** `assignees`
- **Category:** Missing Parameter Boundary Validation
- **CWE:** CWE-400

**Description:**
Parameter 'assignees' does not define 'maxItems'. Large payload arrays could trigger context window exhaustion or memory consumption.

**Remediation:**
> Specify 'maxItems' in the JSON Schema definition for array inputs.

---

### 7. [LOW] Unbounded Array Input on 'issue_fields'

- **Tool Name:** `issue_write`
- **Parameter:** `issue_fields`
- **Category:** Missing Parameter Boundary Validation
- **CWE:** CWE-400

**Description:**
Parameter 'issue_fields' does not define 'maxItems'. Large payload arrays could trigger context window exhaustion or memory consumption.

**Remediation:**
> Specify 'maxItems' in the JSON Schema definition for array inputs.

---

### 8. [LOW] Unbounded Array Input on 'labels'

- **Tool Name:** `issue_write`
- **Parameter:** `labels`
- **Category:** Missing Parameter Boundary Validation
- **CWE:** CWE-400

**Description:**
Parameter 'labels' does not define 'maxItems'. Large payload arrays could trigger context window exhaustion or memory consumption.

**Remediation:**
> Specify 'maxItems' in the JSON Schema definition for array inputs.

---

### 9. [LOW] Unbounded Array Input on 'fields'

- **Tool Name:** `list_commits`
- **Parameter:** `fields`
- **Category:** Missing Parameter Boundary Validation
- **CWE:** CWE-400

**Description:**
Parameter 'fields' does not define 'maxItems'. Large payload arrays could trigger context window exhaustion or memory consumption.

**Remediation:**
> Specify 'maxItems' in the JSON Schema definition for array inputs.

---

### 10. [LOW] Unbounded Array Input on 'cwes'

- **Tool Name:** `list_global_security_advisories`
- **Parameter:** `cwes`
- **Category:** Missing Parameter Boundary Validation
- **CWE:** CWE-400

**Description:**
Parameter 'cwes' does not define 'maxItems'. Large payload arrays could trigger context window exhaustion or memory consumption.

**Remediation:**
> Specify 'maxItems' in the JSON Schema definition for array inputs.

---

### 11. [LOW] Unbounded Array Input on 'field_filters'

- **Tool Name:** `list_issues`
- **Parameter:** `field_filters`
- **Category:** Missing Parameter Boundary Validation
- **CWE:** CWE-400

**Description:**
Parameter 'field_filters' does not define 'maxItems'. Large payload arrays could trigger context window exhaustion or memory consumption.

**Remediation:**
> Specify 'maxItems' in the JSON Schema definition for array inputs.

---

### 12. [LOW] Unbounded Array Input on 'fields'

- **Tool Name:** `list_issues`
- **Parameter:** `fields`
- **Category:** Missing Parameter Boundary Validation
- **CWE:** CWE-400

**Description:**
Parameter 'fields' does not define 'maxItems'. Large payload arrays could trigger context window exhaustion or memory consumption.

**Remediation:**
> Specify 'maxItems' in the JSON Schema definition for array inputs.

---

### 13. [LOW] Unbounded Array Input on 'labels'

- **Tool Name:** `list_issues`
- **Parameter:** `labels`
- **Category:** Missing Parameter Boundary Validation
- **CWE:** CWE-400

**Description:**
Parameter 'labels' does not define 'maxItems'. Large payload arrays could trigger context window exhaustion or memory consumption.

**Remediation:**
> Specify 'maxItems' in the JSON Schema definition for array inputs.

---

### 14. [LOW] Unbounded Array Input on 'fields'

- **Tool Name:** `list_pull_requests`
- **Parameter:** `fields`
- **Category:** Missing Parameter Boundary Validation
- **CWE:** CWE-400

**Description:**
Parameter 'fields' does not define 'maxItems'. Large payload arrays could trigger context window exhaustion or memory consumption.

**Remediation:**
> Specify 'maxItems' in the JSON Schema definition for array inputs.

---

### 15. [LOW] Unbounded Array Input on 'fields'

- **Tool Name:** `list_releases`
- **Parameter:** `fields`
- **Category:** Missing Parameter Boundary Validation
- **CWE:** CWE-400

**Description:**
Parameter 'fields' does not define 'maxItems'. Large payload arrays could trigger context window exhaustion or memory consumption.

**Remediation:**
> Specify 'maxItems' in the JSON Schema definition for array inputs.

---

### 16. [LOW] Unbounded Array Input on 'field_names'

- **Tool Name:** `projects_get`
- **Parameter:** `field_names`
- **Category:** Missing Parameter Boundary Validation
- **CWE:** CWE-400

**Description:**
Parameter 'field_names' does not define 'maxItems'. Large payload arrays could trigger context window exhaustion or memory consumption.

**Remediation:**
> Specify 'maxItems' in the JSON Schema definition for array inputs.

---

### 17. [LOW] Unbounded Array Input on 'fields'

- **Tool Name:** `projects_get`
- **Parameter:** `fields`
- **Category:** Missing Parameter Boundary Validation
- **CWE:** CWE-400

**Description:**
Parameter 'fields' does not define 'maxItems'. Large payload arrays could trigger context window exhaustion or memory consumption.

**Remediation:**
> Specify 'maxItems' in the JSON Schema definition for array inputs.

---

### 18. [LOW] Unbounded Array Input on 'field_names'

- **Tool Name:** `projects_list`
- **Parameter:** `field_names`
- **Category:** Missing Parameter Boundary Validation
- **CWE:** CWE-400

**Description:**
Parameter 'field_names' does not define 'maxItems'. Large payload arrays could trigger context window exhaustion or memory consumption.

**Remediation:**
> Specify 'maxItems' in the JSON Schema definition for array inputs.

---

### 19. [LOW] Unbounded Array Input on 'fields'

- **Tool Name:** `projects_list`
- **Parameter:** `fields`
- **Category:** Missing Parameter Boundary Validation
- **CWE:** CWE-400

**Description:**
Parameter 'fields' does not define 'maxItems'. Large payload arrays could trigger context window exhaustion or memory consumption.

**Remediation:**
> Specify 'maxItems' in the JSON Schema definition for array inputs.

---

### 20. [LOW] Unbounded Array Input on 'items'

- **Tool Name:** `projects_write`
- **Parameter:** `items`
- **Category:** Missing Parameter Boundary Validation
- **CWE:** CWE-400

**Description:**
Parameter 'items' does not define 'maxItems'. Large payload arrays could trigger context window exhaustion or memory consumption.

**Remediation:**
> Specify 'maxItems' in the JSON Schema definition for array inputs.

---

### 21. [LOW] Unbounded Array Input on 'iterations'

- **Tool Name:** `projects_write`
- **Parameter:** `iterations`
- **Category:** Missing Parameter Boundary Validation
- **CWE:** CWE-400

**Description:**
Parameter 'iterations' does not define 'maxItems'. Large payload arrays could trigger context window exhaustion or memory consumption.

**Remediation:**
> Specify 'maxItems' in the JSON Schema definition for array inputs.

---

### 22. [LOW] Unbounded Array Input on 'visible_field_names'

- **Tool Name:** `projects_write`
- **Parameter:** `visible_field_names`
- **Category:** Missing Parameter Boundary Validation
- **CWE:** CWE-400

**Description:**
Parameter 'visible_field_names' does not define 'maxItems'. Large payload arrays could trigger context window exhaustion or memory consumption.

**Remediation:**
> Specify 'maxItems' in the JSON Schema definition for array inputs.

---

### 23. [LOW] Unbounded Array Input on 'visible_fields'

- **Tool Name:** `projects_write`
- **Parameter:** `visible_fields`
- **Category:** Missing Parameter Boundary Validation
- **CWE:** CWE-400

**Description:**
Parameter 'visible_fields' does not define 'maxItems'. Large payload arrays could trigger context window exhaustion or memory consumption.

**Remediation:**
> Specify 'maxItems' in the JSON Schema definition for array inputs.

---

### 24. [LOW] Unbounded Array Input on 'files'

- **Tool Name:** `push_files`
- **Parameter:** `files`
- **Category:** Missing Parameter Boundary Validation
- **CWE:** CWE-400

**Description:**
Parameter 'files' does not define 'maxItems'. Large payload arrays could trigger context window exhaustion or memory consumption.

**Remediation:**
> Specify 'maxItems' in the JSON Schema definition for array inputs.

---

### 25. [LOW] Unbounded Array Input on 'fields'

- **Tool Name:** `search_code`
- **Parameter:** `fields`
- **Category:** Missing Parameter Boundary Validation
- **CWE:** CWE-400

**Description:**
Parameter 'fields' does not define 'maxItems'. Large payload arrays could trigger context window exhaustion or memory consumption.

**Remediation:**
> Specify 'maxItems' in the JSON Schema definition for array inputs.

---

### 26. [LOW] Unbounded Array Input on 'fields'

- **Tool Name:** `search_issues`
- **Parameter:** `fields`
- **Category:** Missing Parameter Boundary Validation
- **CWE:** CWE-400

**Description:**
Parameter 'fields' does not define 'maxItems'. Large payload arrays could trigger context window exhaustion or memory consumption.

**Remediation:**
> Specify 'maxItems' in the JSON Schema definition for array inputs.

---

### 27. [LOW] Unbounded Array Input on 'fields'

- **Tool Name:** `search_pull_requests`
- **Parameter:** `fields`
- **Category:** Missing Parameter Boundary Validation
- **CWE:** CWE-400

**Description:**
Parameter 'fields' does not define 'maxItems'. Large payload arrays could trigger context window exhaustion or memory consumption.

**Remediation:**
> Specify 'maxItems' in the JSON Schema definition for array inputs.

---

### 28. [LOW] Unbounded Array Input on 'reviewers'

- **Tool Name:** `update_pull_request`
- **Parameter:** `reviewers`
- **Category:** Missing Parameter Boundary Validation
- **CWE:** CWE-400

**Description:**
Parameter 'reviewers' does not define 'maxItems'. Large payload arrays could trigger context window exhaustion or memory consumption.

**Remediation:**
> Specify 'maxItems' in the JSON Schema definition for array inputs.

---
