# PortSwigger Web Security Academy

PortSwigger Web Security Academy 학습 기록을 정리하는 저장소입니다.

## 목차

| # | 주제 | 디렉토리 |
|---|------|----------|
| 01 | SQL Injection | [01-sqli](./01-sqli) |
| 02 | Cross-Site Scripting (XSS) | [02-xss](./02-xss) |
| 03 | Cross-Site Request Forgery (CSRF) | [03-csrf](./03-csrf) |
| 04 | Clickjacking | [04-clickjacking](./04-clickjacking) |
| 05 | DOM-based Vulnerabilities | [05-dom-based-vulnerabilities](./05-dom-based-vulnerabilities) |
| 06 | Cross-Origin Resource Sharing (CORS) | [06-cross-origin-resource-sharing](./06-cross-origin-resource-sharing) |
| 07 | XML External Entity (XXE) Injection | [07-xxe-injection](./07-xxe-injection) |
| 08 | Server-Side Request Forgery (SSRF) | [08-ssrf](./08-ssrf) |
| 09 | HTTP Request Smuggling | [09-request-smuggling](./09-request-smuggling) |
| 10 | OS Command Injection | [10-os-command-injection](./10-os-command-injection) |
| 11 | Server-Side Template Injection (SSTI) | [11-ssti](./11-ssti) |
| 12 | Path Traversal | [12-path-traversal](./12-path-traversal) |
| 13 | Access Control | [13-access-control](./13-access-control) |
| 14 | Authentication | [14-authentication](./14-authentication) |

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
| 024 | [Exploiting XSS to perform CSRF](./02-xss/024-xss-exploiting-csrf.md) | Practitioner |
| 025 | [Reflected XSS with AngularJS sandbox escape without strings](./02-xss/025-xss-angular-sandbox-escape-without-strings.md) | Expert |
| 026 | [Reflected XSS with AngularJS sandbox escape and CSP](./02-xss/026-xss-angular-sandbox-escape-and-csp.md) | Expert |
| 027 | [Reflected XSS with event handlers and href attributes blocked](./02-xss/027-xss-event-handlers-href-blocked.md) | Expert |
| 028 | [Reflected XSS in a JavaScript URL with some characters blocked](./02-xss/028-xss-javascript-url-characters-blocked.md) | Expert |
| 029 | [Reflected XSS protected by very strict CSP, with dangling markup attack](./02-xss/029-xss-csp-dangling-markup.md) | Practitioner |
| 030 | [Reflected XSS protected by CSP, with CSP bypass](./02-xss/030-xss-csp-bypass.md) | Expert |

### 03. Cross-Site Request Forgery (CSRF)

| # | 랩 | 난이도 |
|---|-----|--------|
| 001 | [CSRF vulnerability with no defenses](./03-csrf/001-csrf-no-defenses.md) | Apprentice |
| 002 | [CSRF where token validation depends on request method](./03-csrf/002-csrf-token-validation-depends-on-request-method.md) | Practitioner |
| 003 | [CSRF where token validation depends on token being present](./03-csrf/003-csrf-token-validation-depends-on-token-being-present.md) | Practitioner |
| 004 | [CSRF where token is not tied to user session](./03-csrf/004-csrf-token-not-tied-to-user-session.md) | Practitioner |
| 005 | [CSRF where token is tied to non-session cookie](./03-csrf/005-csrf-token-tied-to-non-session-cookie.md) | Practitioner |
| 006 | [CSRF where token is duplicated in cookie](./03-csrf/006-csrf-token-duplicated-in-cookie.md) | Practitioner |
| 007 | [SameSite Lax bypass via method override](./03-csrf/007-csrf-samesite-lax-bypass-method-override.md) | Practitioner |
| 008 | [SameSite Strict bypass via client-side redirect](./03-csrf/008-csrf-samesite-strict-bypass-client-side-redirect.md) | Practitioner |
| 009 | [SameSite Strict bypass via sibling domain](./03-csrf/009-csrf-samesite-strict-bypass-sibling-domain.md) | Practitioner |
| 010 | [SameSite Lax bypass via cookie refresh](./03-csrf/010-csrf-samesite-bypass-cookie-refresh.md) | Practitioner |
| 011 | [CSRF where Referer validation depends on header being present](./03-csrf/011-csrf-referer-validation-depends-on-header-being-present.md) | Practitioner |
| 012 | [CSRF with broken Referer validation](./03-csrf/012-csrf-referer-validation-broken.md) | Practitioner |

### 04. Clickjacking

| # | 랩 | 난이도 |
|---|-----|--------|
| 001 | [Basic clickjacking with CSRF token protection](./04-clickjacking/001-clickjacking-basic-csrf-protected.md) | Apprentice |
| 002 | [Clickjacking with form input data prefilled from a URL parameter](./04-clickjacking/002-clickjacking-prefilled-form-input.md) | Apprentice |
| 003 | [Clickjacking with a frame buster script](./04-clickjacking/003-clickjacking-frame-buster-script.md) | Apprentice |
| 004 | [Exploiting clickjacking vulnerability to trigger DOM-based XSS](./04-clickjacking/004-clickjacking-dom-xss.md) | Practitioner |
| 005 | [Multistep clickjacking](./04-clickjacking/005-clickjacking-multistep.md) | Practitioner |

### 05. DOM-based Vulnerabilities

| # | 랩 | 난이도 |
|---|-----|--------|
| 001 | [DOM XSS using web messages](./05-dom-based-vulnerabilities/001-dom-xss-web-messages.md) | Apprentice |
| 002 | [DOM XSS using web messages and a JavaScript URL](./05-dom-based-vulnerabilities/002-dom-xss-web-messages-javascript-url.md) | Apprentice |
| 003 | [DOM XSS using web messages and JSON.parse](./05-dom-based-vulnerabilities/003-dom-xss-web-messages-json-parse.md) | Apprentice |
| 004 | [DOM-based open redirection](./05-dom-based-vulnerabilities/004-dom-open-redirection.md) | Apprentice |
| 005 | [DOM-based cookie manipulation](./05-dom-based-vulnerabilities/005-dom-cookie-manipulation.md) | Practitioner |
| 006 | [DOM XSS exploiting DOM clobbering](./05-dom-based-vulnerabilities/006-dom-xss-dom-clobbering.md) | Expert |
| 007 | [DOM clobbering to bypass HTML filters](./05-dom-based-vulnerabilities/007-dom-clobbering-bypass-html-filters.md) | Expert |

### 06. Cross-Origin Resource Sharing (CORS)

| # | 랩 | 난이도 |
|---|-----|--------|
| 001 | [CORS vulnerability with basic origin reflection](./06-cross-origin-resource-sharing/001-cors-basic-origin-reflection.md) | Apprentice |
| 002 | [CORS vulnerability with trusted null origin](./06-cross-origin-resource-sharing/002-cors-null-origin-whitelisted.md) | Apprentice |
| 003 | [CORS vulnerability with trusted insecure protocols](./06-cross-origin-resource-sharing/003-cors-breaking-https.md) | Practitioner |

### 07. XML External Entity (XXE) Injection

| # | 랩 | 난이도 |
|---|-----|--------|
| 001 | [Exploiting XXE using external entities to retrieve files](./07-xxe-injection/001-xxe-retrieve-files.md) | Apprentice |
| 002 | [Exploiting XXE to perform SSRF attacks](./07-xxe-injection/002-xxe-ssrf.md) | Apprentice |
| 003 | [Blind XXE with out-of-band interaction](./07-xxe-injection/003-xxe-blind-oob.md) | Practitioner |
| 004 | [Blind XXE with out-of-band interaction using XML parameter entities](./07-xxe-injection/004-xxe-blind-oob-parameter-entities.md) | Practitioner |
| 005 | [Exploiting blind XXE to exfiltrate data using a malicious external DTD](./07-xxe-injection/005-xxe-blind-exfiltration.md) | Practitioner |
| 006 | [Exploiting blind XXE to retrieve data via error messages](./07-xxe-injection/006-xxe-blind-error-based.md) | Practitioner |
| 007 | [Exploiting XInclude to retrieve files](./07-xxe-injection/007-xxe-xinclude.md) | Practitioner |
| 008 | [Exploiting XXE via image file upload](./07-xxe-injection/008-xxe-file-upload.md) | Practitioner |
| 009 | [Exploiting XXE to inject through a local DTD](./07-xxe-injection/009-xxe-local-dtd.md) | Expert |

### 08. Server-Side Request Forgery (SSRF)

| # | 랩 | 난이도 |
|---|-----|--------|
| 001 | [Basic SSRF against the local server](./08-ssrf/001-ssrf-basic-localhost.md) | Apprentice |
| 002 | [Basic SSRF against another back-end system](./08-ssrf/002-ssrf-basic-backend-system.md) | Apprentice |
| 003 | [Blind SSRF with out-of-band detection](./08-ssrf/003-ssrf-blind-oob-detection.md) | Practitioner |
| 004 | [SSRF with blacklist-based input filter](./08-ssrf/004-ssrf-blacklist-filter.md) | Practitioner |
| 005 | [SSRF with filter bypass via open redirection](./08-ssrf/005-ssrf-open-redirect-filter-bypass.md) | Practitioner |
| 006 | [Blind SSRF with Shellshock exploitation](./08-ssrf/006-ssrf-blind-shellshock.md) | Expert |
| 007 | [SSRF with whitelist-based input filter](./08-ssrf/007-ssrf-whitelist-filter.md) | Expert |

### 09. HTTP Request Smuggling

| # | 랩 | 난이도 |
|---|-----|--------|
| 001 | [HTTP request smuggling, confirming a CL.TE vulnerability via differential responses](./09-request-smuggling/001-cl-te-differential-response.md) | Practitioner |
| 002 | [HTTP request smuggling, confirming a TE.CL vulnerability via differential responses](./09-request-smuggling/002-te-cl-differential-response.md) | Practitioner |
| 003 | [Bypassing front-end security controls, CL.TE vulnerability](./09-request-smuggling/003-cl-te-bypass-frontend-controls.md) | Practitioner |
| 004 | [Bypassing front-end security controls, TE.CL vulnerability](./09-request-smuggling/004-te-cl-bypass-frontend-controls.md) | Practitioner |
| 005 | [Revealing front-end request rewriting](./09-request-smuggling/005-reveal-frontend-rewriting.md) | Practitioner |
| 006 | [Capturing other users' requests](./09-request-smuggling/006-capture-other-users-requests.md) | Practitioner |
| 007 | [Exploiting HTTP request smuggling to deliver reflected XSS](./09-request-smuggling/007-deliver-reflected-xss.md) | Practitioner |
| 008 | [H2.TE request smuggling — Response queue poisoning](./09-request-smuggling/008-h2-response-queue-poisoning-te.md) | Expert |

### 10. OS Command Injection

| # | 랩 | 난이도 |
|---|-----|--------|
| 001 | [OS command injection, simple case](./10-os-command-injection/001-os-command-injection-simple.md) | Apprentice |
| 002 | [Blind OS command injection with time delays](./10-os-command-injection/002-blind-time-delays.md) | Practitioner |
| 003 | [Blind OS command injection with output redirection](./10-os-command-injection/003-blind-output-redirection.md) | Practitioner |
| 004 | [Blind OS command injection with out-of-band interaction](./10-os-command-injection/004-blind-oob-interaction.md) | Practitioner |
| 005 | [Blind OS command injection with out-of-band data exfiltration](./10-os-command-injection/005-blind-oob-data-exfiltration.md) | Practitioner |

### 11. Server-Side Template Injection (SSTI)

| # | 랩 | 난이도 |
|---|-----|--------|
| 001 | [Basic server-side template injection](./11-ssti/001-ssti-basic.md) | Apprentice |
| 002 | [Basic server-side template injection (code context)](./11-ssti/002-ssti-basic-code-context.md) | Apprentice |
| 003 | [Server-side template injection using documentation](./11-ssti/003-ssti-using-documentation.md) | Practitioner |
| 004 | [Server-side template injection in an unknown language with a documented exploit](./11-ssti/004-ssti-unknown-language-handlebars.md) | Practitioner |
| 005 | [Server-side template injection with information disclosure via user-supplied objects](./11-ssti/005-ssti-information-disclosure-django.md) | Practitioner |
| 006 | [Server-side template injection in a sandboxed environment](./11-ssti/006-ssti-sandboxed-environment.md) | Expert |
| 007 | [Server-side template injection with a custom exploit](./11-ssti/007-ssti-custom-exploit-twig.md) | Expert |

### 12. Path Traversal

| # | 랩 | 난이도 |
|---|-----|--------|
| 001 | [File path traversal, simple case](./12-path-traversal/001-path-traversal-simple.md) | Apprentice |
| 002 | [File path traversal, traversal sequences blocked with absolute path bypass](./12-path-traversal/002-path-traversal-absolute-path-bypass.md) | Practitioner |
| 003 | [File path traversal, traversal sequences stripped non-recursively](./12-path-traversal/003-path-traversal-sequences-stripped-non-recursively.md) | Practitioner |
| 004 | [File path traversal, traversal sequences stripped with superfluous URL-decode](./12-path-traversal/004-path-traversal-superfluous-url-decode.md) | Practitioner |
| 005 | [File path traversal, validation of start of path](./12-path-traversal/005-path-traversal-validate-start-of-path.md) | Practitioner |
| 006 | [File path traversal, validation of file extension with null byte bypass](./12-path-traversal/006-path-traversal-validate-file-extension-null-byte-bypass.md) | Practitioner |

### 13. Access Control

| # | 랩 | 난이도 |
|---|-----|--------|
| 001 | [Unprotected admin functionality](./13-access-control/001-access-control-unprotected-admin-functionality.md) | Apprentice |
| 002 | [Unprotected admin functionality with unpredictable URL](./13-access-control/002-access-control-unpredictable-url.md) | Apprentice |
| 003 | [User role controlled by request parameter](./13-access-control/003-access-control-role-controlled-by-request-parameter.md) | Apprentice |
| 004 | [User role can be modified in user profile](./13-access-control/004-access-control-role-modified-in-profile.md) | Apprentice |
| 005 | [User ID controlled by request parameter](./13-access-control/005-access-control-user-id-request-parameter.md) | Apprentice |
| 006 | [User ID controlled by request parameter, with unpredictable user IDs](./13-access-control/006-access-control-unpredictable-user-ids.md) | Apprentice |
| 007 | [User ID controlled by request parameter with data leakage in redirect](./13-access-control/007-access-control-data-leakage-in-redirect.md) | Apprentice |
| 008 | [User ID controlled by request parameter with password disclosure](./13-access-control/008-access-control-user-id-password-disclosure.md) | Apprentice |
| 009 | [Insecure direct object references](./13-access-control/009-access-control-idor.md) | Apprentice |
| 010 | [URL-based access control can be circumvented](./13-access-control/010-access-control-url-based-circumvented.md) | Practitioner |
| 011 | [Method-based access control can be circumvented](./13-access-control/011-access-control-method-based-circumvented.md) | Practitioner |
| 012 | [Multi-step process with no access control on one step](./13-access-control/012-access-control-multi-step-process.md) | Practitioner |
| 013 | [Referer-based access control](./13-access-control/013-access-control-referer-based.md) | Practitioner |

### 14. Authentication

| # | 랩 | 난이도 |
|---|-----|--------|
| 001 | [Username enumeration via different responses](./14-authentication/001-authentication-username-enumeration-different-responses.md) | Apprentice |
| 002 | [2FA simple bypass](./14-authentication/002-authentication-2fa-simple-bypass.md) | Apprentice |
| 003 | [Password reset broken logic](./14-authentication/003-authentication-password-reset-broken-logic.md) | Practitioner |
| 004 | [Username enumeration via subtly different responses](./14-authentication/004-authentication-username-enumeration-subtly-different-responses.md) | Apprentice |
| 005 | [Username enumeration via response timing](./14-authentication/005-authentication-username-enumeration-response-timing.md) | Practitioner |
| 006 | [Broken brute-force protection, IP block](./14-authentication/006-authentication-broken-bruteforce-protection-ip-block.md) | Practitioner |
| 007 | [Username enumeration via account lock](./14-authentication/007-authentication-username-enumeration-account-lock.md) | Practitioner |
| 008 | [2FA broken logic](./14-authentication/008-authentication-2fa-broken-logic.md) | Practitioner |
