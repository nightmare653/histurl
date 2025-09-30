# histurl
it just retrives urls from different archive sites and gives it to you seperating the urls and js urls


# histurl — Historical URL Harvester (What this code does)

This program collects **historical URLs** for one or more domains from multiple **free sources**, merges and de-duplicates them, then performs several post-processing steps:

1. **Splits out JavaScript URLs**.
2. **Flags possible secrets** in URL strings (and optionally in fetched content).
3. **Classifies “interesting file” URLs** (e.g., `.json`, `.pdf`, `.sql`, `.zip`, `.tar.gz`, `.env`, etc.) and saves them **per-extension**.
4. Writes **per-domain** outputs and **merged “ALL_*”** outputs across all domains.

It’s designed for recon/bug bounty pipelines where you want **maximum historical coverage without crawling**.

---

## Data sources (no crawling)

The program queries these sources **in parallel** and aggregates their results:

* **Internet Archive CDX** (paged):

  * Endpoint: `https://web.archive.org/cdx/search/cdx`
  * Uses `limit` + `showResumeKey` pagination to safely walk very large datasets without timing out.
  * Collapses by `urlkey` to reduce duplicates and returns only the `original` field (URL).

* **waybackurls** (external tool; tomnomnom):

  * Executed as a subprocess: `waybackurls <domain>`.
  * Outputs lines of URLs gathered from Wayback Machine.

* **gau / gauplus** (external tool):

  * Prefers `gauplus` when available; falls back to `gau`.
  * Executed as a subprocess: `gauplus <domain>` or `gau <domain>`.

* **urlscan.io** (search API):

  * Endpoint: `/api/v1/search/?q=domain:<domain>&size=10000`
  * Supports pagination via `has_more` + `next` (`search_after` tokens).

* **AlienVault OTX** (domain URL list):

  * Correct endpoint: `/api/v1/indicators/domain/<domain>/url_list?limit=500&page=N`
  * Paginates until `has_more=false`.

* **VirusTotal v2** (domain report):

  * Endpoint: `/vtapi/v2/domain/report?apikey=<embedded>&domain=<domain>`
  * Collects both `detected_urls` and `undetected_urls`.

> All collectors run concurrently behind a small semaphore to be polite to remote services. Each request includes a configurable **politeness delay**.

---

## Processing pipeline (per domain)

1. **Collect**
   For each domain, all above collectors run concurrently. Each collector returns a slice of URLs. Errors from individual collectors are printed to `stderr` but do **not** abort the run.

2. **Merge & de-duplicate**
   Results from all collectors are combined into a single set and de-duplicated (string-level).

3. **Split out JavaScript**
   URLs ending with `\.js` (case-insensitive, query string allowed) are saved separately.

4. **Heuristic secret detection (URL strings)**
   Each URL string is scanned with regex patterns for:

   * Emails
   * AWS Access Key ID (`AKIA...`)
   * Google API keys (`AIza...`)
   * JWTs
   * 32–64 length hex strings
   * “Secret-ish” query parameters (`apikey`, `token`, `x-api-key`, `password`, `client_secret`, etc.)
   * “Interesting” API paths (`/api`, `/graphql`, `/oauth`, `/auth`, `/token`, etc.)

   Matches are written to `findings.txt` with the URL, matched value, and which pattern fired.

5. **(Optional) Fetch page content & scan**
   If `-fetch-content` is set, the program **HTTP GETs** each URL (respecting a 3 MB body cap and reasonable status checks) and runs a **lighter** regex set over the response body (emails, `AKIA`, `AIza`, JWTs, hex strings, generic key=value secret patterns). Any matches are appended to `findings.txt` with source `content`.

   > This increases runtime and traffic; use only when needed and be respectful of targets.

6. **Classify “interesting file” URLs**
   The code classifies URLs whose **path** ends with any of these extensions (case-insensitive; multi-part extensions first so they’re matched correctly):

   ```
   tar.gz,
   sqlitedb, sqlite3,
   xls, xml, xlsx, json, pdf, sql, doc, docx, pptx, txt,
   zip, tgz, bak, 7z, rar, log, cache, secret, db, backup,
   yml, gz, config, csv, yaml, md, md5, tar, xz, 7zip,
   p12, pem, key, crt, csr,
   sh, pl, py, java, class, jar, war, ear,
   dbf, db3, accdb, mdb, sqlcipher,
   gitignore, env, ini, conf, properties, plist, cfg
   ```

   Two outputs are produced:

   * A **flat list** of all matches: `interesting_files.txt`
   * A **folder of per-extension files** under `by_ext/`, e.g. `interesting_json.txt`, `interesting_sql.txt`, `interesting_tar.gz.txt`, etc.

---

## Output layout

For each domain `<domain>`:

```
out/
  <domain>/
    all_urls.txt            # deduped union of all sources
    js_urls.txt             # only *.js
    findings.txt            # regex hits from URL strings (and optional content)
    interesting_files.txt   # all matches from the extension classifier
    by_ext/
      interesting_json.txt
      interesting_sql.txt
      interesting_tar.gz.txt
      ... (one file per extension that had matches)
```

Additionally, **merged** files across all processed domains are written at the top level:

```
out/
  ALL_all_urls.txt
  ALL_js_urls.txt
  ALL_interesting_files.txt
  ALL_by_ext/
    interesting_json.txt
    interesting_sql.txt
    ...
```

---

## Reliability & performance features

* **Concurrency control** for per-domain processing with `-P`.
* **Politeness delay** between calls (`-delay-ms`) to avoid hammering services.
* **Web Archive hardening**:

  * `showResumeKey` + `limit` to page through huge results safely.
  * Per-request timeout just for Web Archive (`-wa-timeout`).
  * Retries for transient failures/5xx (`-wa-retries`).
* **OTX paging** using `limit` and `has_more`.
* **urlscan.io** paging using `search_after` tokens.
* **Content-fetch cap** at 3 MB per response to avoid huge downloads.

---

## CLI flags (behavioral controls)

| Flag             |                                    Default | Purpose                                            |
| ---------------- | -----------------------------------------: | -------------------------------------------------- |
| `-domain`        |                                            | Process a single domain (e.g., `example.com`)      |
| `-domains-file`  |                                            | File with one domain per line                      |
| `-out`           |                                 `out_urls` | Output directory                                   |
| `-P`             |                                        `6` | Domain concurrency                                 |
| `-fetch-content` |                                    `false` | Fetch bodies and scan for secrets (slower, polite) |
| `-delay-ms`      |                                      `200` | Delay between remote requests per collector        |
| `-ua`            | `ReconURLCollector/1.0 (+https://example)` | HTTP User-Agent                                    |
| `-wa-timeout`    |                                      `120` | Web Archive per-request timeout (seconds)          |
| `-wa-retries`    |                                        `4` | Web Archive retry attempts                         |
| `-wa-limit`      |                                    `10000` | CDX page size for `showResumeKey` pagination       |

> The **VirusTotal v2 key is embedded** in the code by design (per your requirement). If you plan to share the repo/binary, move it to an env var or config file to avoid exposing it.

---

## External dependencies

* **Go 1.20+** to build.
* **Optional binaries on `$PATH`**:

  * `waybackurls`
  * `gau` or `gauplus` (prefers `gauplus` if available)

If these tools aren’t installed, their collectors simply return 0 and the rest of the pipeline proceeds.

---

## Typical usage

Process one domain and write results to `out/`:

```bash
histurl -domain example.com -out out
```

Handle big domains more safely against Wayback:

```bash
histurl -domain bigtarget.com -out out \
  -wa-limit 5000 -wa-timeout 180 -wa-retries 6
```

Process many domains concurrently:

```bash
histurl -domains-file scope.txt -out out -P 6
```

Include lightweight content scanning for extra secret hits:

```bash
histurl -domain example.com -out out -fetch-content
```

---

## Notes & caveats

* Regex-based findings are **heuristics**; expect **false positives**. Use them as leads.
* Historical datasets often include **stale URLs** and **dead links**—that’s expected and still valuable (parameters, old endpoints, leaked assets).
* Be mindful of **rate limits** and **terms of service** for each upstream provider.
* For very large scopes, consider splitting per subdomain or time-windowing (the code is already CDX-paged; year filters could be added if you want).

---

## TL;DR

This code:

* Pulls historical URLs for your domain from multiple free sources (CDX, waybackurls, gau/gauplus, urlscan, OTX, VT).
* Dedupes and organizes them.
* Extracts JS file URLs.
* Detects secret-ish patterns in URL strings (and optionally response bodies).
* Separates and saves **interesting file types** (flat + per-extension).
* Writes clean per-domain and merged outputs for downstream tooling.




Made by kHaleel ---> Nightmare neutron
