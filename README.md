# PortSwigger Web Security Academy

PortSwigger Web Security Academy 학습 기록을 정리하는 저장소입니다.

## 목차

| # | 주제 | 디렉토리 |
|---|------|----------|
| 01 | SQL Injection | [01-sqli](./01-sqli) |
| 02 | Cross-Site Scripting (XSS) | [02-xss](./02-xss) |

### 01. SQL Injection

| # | 랩 | 난이도 |
|---|-----|--------|
| 001 | [SQL injection vulnerability in WHERE clause allowing retrieval of hidden data](./01-sqli/001-sqli-where-clause-hidden-data.md) | Apprentice |
| 002 | [SQL injection vulnerability allowing login bypass](./01-sqli/002-sqli-login-bypass.md) | Apprentice |
| 003 | [SQL injection attack, querying the database type and version on Oracle](./01-sqli/003-sqli-querying-database-version-oracle.md) | Practitioner |
| 004 | [SQL injection attack, querying the database type and version on MySQL and Microsoft](./01-sqli/004-sqli-querying-database-version-mysql-microsoft.md) | Practitioner |
| 005 | [SQL injection attack, listing the database contents on non-Oracle databases](./01-sqli/005-sqli-listing-database-contents-non-oracle.md) | Practitioner |
| 006 | [SQL injection attack, listing the database contents on Oracle](./01-sqli/006-sqli-listing-database-contents-oracle.md) | Practitioner |
| 007 | [SQL injection UNION attack, determining the number of columns returned by the query](./01-sqli/007-sqli-determine-number-of-columns.md) | Practitioner |
| 008 | [SQL injection UNION attack, finding a column containing text](./01-sqli/008-sqli-find-column-containing-text.md) | Practitioner |
| 009 | [SQL injection UNION attack, retrieving data from other tables](./01-sqli/009-sqli-retrieve-data-from-other-tables.md) | Practitioner |
| 010 | [SQL injection UNION attack, retrieving multiple values in a single column](./01-sqli/010-sqli-retrieve-multiple-values-in-single-column.md) | Practitioner |
| 011 | [Blind SQL injection with conditional responses](./01-sqli/011-sqli-blind-conditional-responses.md) | Practitioner |
| 012 | [Blind SQL injection with conditional errors](./01-sqli/012-sqli-blind-conditional-errors.md) | Practitioner |
| 013 | [Visible error-based SQL injection](./01-sqli/013-sqli-visible-error-based.md) | Practitioner |
| 014 | [Blind SQL injection with time delays](./01-sqli/014-sqli-blind-time-delays.md) | Practitioner |
| 015 | [Blind SQL injection with time delays and information retrieval](./01-sqli/015-sqli-blind-time-delays-info-retrieval.md) | Practitioner |
| 016 | [Blind SQL injection with out-of-band interaction](./01-sqli/016-sqli-blind-out-of-band.md) | Practitioner |
| 017 | [Blind SQL injection with out-of-band data exfiltration](./01-sqli/017-sqli-blind-out-of-band-data-exfiltration.md) | Practitioner |
| 018 | [SQL injection with filter bypass via XML encoding](./01-sqli/018-sqli-xml-filter-bypass.md) | Practitioner |

### 02. Cross-Site Scripting (XSS)

| # | 랩 | 난이도 |
|---|-----|--------|
| 001 | [Reflected XSS into HTML context with nothing encoded](./02-xss/001-xss-reflected-html-context-nothing-encoded.md) | Apprentice |
| 002 | [Stored XSS into HTML context with nothing encoded](./02-xss/002-xss-stored-html-context-nothing-encoded.md) | Apprentice |
| 003 | [DOM XSS in document.write sink using source location.search](./02-xss/003-xss-dom-document-write-sink.md) | Apprentice |
| 004 | [DOM XSS in innerHTML sink using source location.search](./02-xss/004-xss-dom-innerhtml-sink.md) | Apprentice |
| 005 | [DOM XSS in jQuery anchor href attribute sink using location.search source](./02-xss/005-xss-dom-jquery-href-attribute-sink.md) | Apprentice |
| 006 | [DOM XSS in jQuery selector sink using a hashchange event](./02-xss/006-xss-dom-jquery-selector-hashchange.md) | Apprentice |
| 007 | [Reflected XSS into attribute with angle brackets HTML-encoded](./02-xss/007-xss-reflected-attribute-angle-brackets-encoded.md) | Apprentice |
| 008 | [Stored XSS into anchor href attribute with double quotes HTML-encoded](./02-xss/008-xss-stored-href-attribute-double-quotes-encoded.md) | Apprentice |
| 009 | [Reflected XSS into a JavaScript string with angle brackets HTML encoded](./02-xss/009-xss-reflected-javascript-string-angle-brackets-encoded.md) | Apprentice |
| 010 | [DOM XSS in document.write sink inside a select element](./02-xss/010-xss-dom-document-write-sink-inside-select.md) | Practitioner |
| 011 | [DOM XSS in AngularJS expression with angle brackets and double quotes HTML-encoded](./02-xss/011-xss-dom-angularjs-expression.md) | Practitioner |
| 012 | [Reflected DOM XSS](./02-xss/012-xss-dom-reflected.md) | Practitioner |
| 013 | [Stored DOM XSS](./02-xss/013-xss-dom-stored.md) | Practitioner |
| 014 | [Reflected XSS with most tags and attributes blocked](./02-xss/014-xss-most-tags-attributes-blocked.md) | Practitioner |
| 015 | [Reflected XSS with all tags blocked except custom ones](./02-xss/015-xss-all-tags-blocked-except-custom.md) | Practitioner |
| 016 | [Reflected XSS with some SVG markup allowed](./02-xss/016-xss-svg-markup-allowed.md) | Practitioner |
| 017 | [Reflected XSS in canonical link tag](./02-xss/017-xss-canonical-link-tag.md) | Practitioner |
| 018 | [Reflected XSS into a JavaScript string with single quote and backslash escaped](./02-xss/018-xss-javascript-string-single-quote-backslash-escaped.md) | Practitioner |
| 019 | [Reflected XSS into a JavaScript string with angle brackets and double quotes HTML-encoded and single quotes escaped](./02-xss/019-xss-javascript-string-angle-brackets-double-quotes-encoded-single-quotes-escaped.md) | Practitioner |
| 020 | [Reflected XSS into onclick event with angle brackets and double quotes HTML-encoded and single quotes and backslash escaped](./02-xss/020-xss-onclick-event-angle-brackets-double-quotes-html-encoded-single-quotes-backslash-escaped.md) | Practitioner |
| 021 | [Reflected XSS into a JavaScript template literal with angle brackets, single, double quotes, backslash and backticks Unicode-escaped](./02-xss/021-xss-javascript-template-literal-angle-brackets-single-double-quotes-backslash-backticks-escaped.md) | Practitioner |
| 022 | [Exploiting cross-site scripting to steal cookies](./02-xss/022-xss-exploiting-stealing-cookies.md) | Practitioner |
| 023 | [Exploiting cross-site scripting to capture passwords](./02-xss/023-xss-exploiting-capturing-passwords.md) | Practitioner |
