# Lab: User ID controlled by request parameter with data leakage in redirect

## 개요

- **난이도**: Apprentice
- **주제**: Access Control — 수평적 권한 상승 / IDOR / 리다이렉트 응답 body 데이터 유출
- **링크**: https://portswigger.net/web-security/access-control/lab-user-id-controlled-by-request-parameter-with-data-leakage-in-redirect

## 목표

계정 페이지의 `id` 를 `carlos` 로 바꾸면 `/login` 으로 리다이렉트되지만, **302 응답 body 에 carlos 의 정보가 포함**된다. 이 body 에서 API 키를 획득해 제출한다.

- 계정: `wiener:peter`

## 이전 랩(005, 006)과의 차이

```
[005 / 006 — 데이터 직접 반환]
  id 변조 → 200 응답 body 에 타 사용자 정보 반환

[007 — 리다이렉트 + body 유출 (이번)]
  id 변조 → 302 /login (겉보기엔 접근 차단)
  그러나 302 응답 body 안에 carlos 데이터가 이미 포함
```

핵심: **리다이렉트는 "접근 거부" 가 아니다. 응답 body 에 데이터가 담겨 있으면
브라우저가 리다이렉트를 따라가더라도 공격자는 body 를 읽을 수 있다.**

## 취약 지점

### 접근 제어가 "응답을 만든 뒤" 적용되는 구조

```
[요청]
  GET /my-account?id=carlos
  Cookie: session=<wiener 세션>

[서버 처리 — 취약한 순서]
  1) id=carlos 로 계정 정보를 조회하고 페이지를 렌더링/직렬화  ← 데이터 생성
  2) 세션 사용자(wiener)와 불일치 확인
  3) 302 Location: /login 응답                              ← 리다이렉트

[결과]
  상태코드: 302
  body    : carlos 의 계정 HTML (API 키 포함)
```

정상적인 방어라면 1) 전에 소유자 검사를 해서 `403` 을 반환하고
어떤 데이터도 생성/포함하지 않아야 한다.

## 공격 단계

### 1단계 — 로그인 후 계정 페이지 확인

`wiener:peter` 로 로그인하고 `/my-account?id=<wiener>` 요청을 Burp 로 캡처한다.

```
GET /my-account?id=wiener HTTP/1.1
Cookie: session=<wiener 세션>
```

### 2단계 — id 를 carlos 로 변조

요청을 Repeater 로 보내 `id` 를 `carlos` 로 바꾼다.

```
GET /my-account?id=carlos HTTP/1.1
Cookie: session=<wiener 세션>
```

### 3단계 — 302 응답의 body 확인

응답 헤더만 보면 리다이렉트로 보인다.

```
HTTP/1.1 302 Found
Location: /login
```

그러나 **응답 body** 에 carlos 의 계정 정보가 포함되어 있다.

```html
<div id="account-content">
  <p>Your username is: carlos</p>
  <p>Your email is: carlos@...net</p>
  <div>Your API Key is: <span>...</span></div>
</div>
```

Burp 에서는 `Response` 탭(또는 "Render" 가 아닌 raw)에서 body 를 확인한다.
브라우저는 자동으로 `/login` 으로 이동하므로 눈으로는 안 보일 수 있다.

### 4단계 — API 키 제출

확인한 carlos 의 API 키를 제출해 랩 해결.

## 리다이렉트와 데이터 유출

```
[브라우저의 동작]
  302 응답을 받으면 Location 헤더로 즉시 이동
  → body 를 사용자에게 렌더링하지 않음

[공격자의 동작]
  브라우저를 거치지 않고 프록시(Burp)/스크립트로 직접 요청
  → 302 응답 자체를 가로채 body 를 읽음

[방어 관점]
  "사용자가 못 볼 것" = "노출되지 않음" 이 아니다.
  응답에 데이터를 "담지 않는 것" 이 보안이다.
```

## 방어

```
[근본 원인]
  인가 검사 전에 데이터를 조회/직렬화하여 리다이렉트 응답 body 에 포함

[올바른 방어 — 검사 우선 순서]
  1. 요청 진입 시 가장 먼저 소유자/권한 검사
  2. 권한 없으면 즉시 403 (또는 데이터 없는 빈 404)
     - 민감 데이터를 조회/렌더링하지 않음
  3. 데이터 생성은 인가 통과 후에만 수행
  4. 리다이렉트로 접근을 "돌리는" 방식에 의존하지 않음

[안티패턴]
  데이터를 먼저 만든 뒤 "로그인 안 됐으면 redirect" 처리
  → 302 응답 body 에 데이터가 남음

[검증 포인트]
  모든 3xx 응답의 body 에 민감 데이터가 없는지 점검
```

## 핵심 정리

- `id=carlos` 요청이 `/login` 으로 리다이렉트되어 접근이 막힌 것처럼 보였지만, 302 응답 body 에 API 키가 포함되어 있었다.
- 리다이렉트는 데이터 노출을 막지 못한다. 공격자는 프록시로 응답 자체를 읽는다.
- 원인은 소유자 검사 이전에 데이터를 조회·직렬화한 순서 문제다.
- 방어는 인가 검사를 최우선으로 수행하고, 권한 없으면 데이터 없는 응답(403)을 반환하는 것이다.

## 배운 점

- 005/006 은 데이터가 200 응답으로 직접 반환됐고, 007 은 302 리다이렉트 뒤에 숨어 있었다.
- Burp Suite 로 작업할 때 리다이렉트 응답도 자동 추적에 의존하지 말고 원본 응답(Latest response / raw body)을 반드시 확인해야 한다.
- 접근 제어의 정석은 "허용 여부 판단 → 데이터 처리" 순서이며, 순서가 뒤바뀌면 차단처럼 보이는 응답에서도 정보가 새어 나간다.
