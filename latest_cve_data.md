```
 curl https://cvedb.shodan.io/cves | jq '.cves | reverse | .[:10] | .[] | {
  CVE: (.cve_id // "Not Available"),
  CVSS: (.cvss // "Not Available"),
  CVSS_v2: (.cvss_v2 // "Not Available"),
  CVSS_v3: (.cvss_v3 // "Not Available"),
  EPSS: (.epss // "Not Available"),
  KEV: (.kev // "Not Available"),
  Published: (.published_time // "Not Available"),
  References: (.references // ["No references available"]),
  Summary: (.summary // "Not Available")
}'
```
