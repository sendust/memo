# memo – 텔레그램 봇 웹 메신저 (Cloudflare Worker)

텔레그램 봇으로 받은 메시지를 **웹 브라우저에서 확인하고 답장**할 수 있게 해 주는 개인용 웹앱입니다.
서버는 Cloudflare Worker 파일 하나(`src/worker.js`)로 동작하고, 별도 서버나 유료 서비스가 필요 없습니다.

- 봇 토큰·PIN은 Worker 시크릿에만 저장되고, 브라우저에는 노출되지 않습니다.
- 개인 사용량이라면 Cloudflare 무료 플랜 범위 안에서 동작합니다.

---

## 목차

1. [주요 기능](#1-주요-기능)
2. [구성](#2-구성)
3. [설치 – 대시보드로 처음부터 만들기](#3-설치--대시보드로-처음부터-만들기)
4. [설치 – Wrangler CLI로 배포하기 (선택)](#4-설치--wrangler-cli로-배포하기-선택)
5. [사용법](#5-사용법)
6. [설정값 정리](#6-설정값-정리)
7. [코드 수정·배포 방법 (미리보기 → 배포)](#7-코드-수정배포-방법-미리보기--배포)
8. [API 목록](#8-api-목록)
9. [보안](#9-보안)
10. [문제 해결](#10-문제-해결)

---

## 1. 주요 기능

| 기능 | 설명 |
|---|---|
| 💬 메시지 확인·답장 | 🔄 버튼으로 새 메시지를 가져오고(getUpdates), 텍스트·파일을 보냅니다. |
| 📁 파일 송수신 | 사진·문서 업로드(최대 50MB), 다운로드(최대 20MB), 끌어다 놓기·붙여넣기 지원 |
| 🖼️ / 💾 이미지 전송 방식 | 토글 버튼으로 사진(`sendPhoto`, 압축) 또는 원본 파일(`sendDocument`, 무압축) 선택 |
| ✂ 긴 메시지 | 4,096자를 넘으면 "나눠 보내기" 또는 ".txt 파일로 보내기" 선택 |
| ⤢ 큰 입력창 | 확장 버튼으로 여러 줄 입력 모드 (Enter 줄바꿈 · Ctrl+Enter 전송) |
| 🗂 여러 봇 (탭) | API 토큰으로 봇을 추가·제거하고 탭으로 전환. 추가 봇 토큰은 서버에 암호화 저장 |
| 🗄 서버 저장 | 봇·대화방마다 최근 N개 메시지를 D1에 저장 → 다른 PC에서도 같은 기록 |
| 📋 복사 / ✕ 삭제 | 메시지 복사, 메시지·대화방 기록 삭제(서버+브라우저, 텔레그램에는 남음) |
| 🔒 PIN 로그인 | PIN 5회 실패 시 해당 IP 1시간 차단, 세션 12시간 |
| 📱 텔레그램 승인 로그인 | "인증요청" → 내 텔레그램으로 온 메시지에서 [허가하기] → 짧은 임시 세션으로 입장 |
| 🕶 임시 세션 제한 | 승인 로그인 세션에서는 저장된 기록을 보여주지 않고, 그 세션에서 새로 받은 메시지만 표시 |

---

## 2. 구성

```
브라우저 ──HTTPS──▶ Cloudflare Worker (src/worker.js)
                      ├─ Secret   : BOT_TOKEN, PIN, AUTHBOT_TOKEN, (SESSION_SECRET)
                      ├─ Variable : KEEP_PER_CHAT, ONETIME_SESSION_SEC, AUTH_CHAT_ID
                      ├─ KV  BANS : PIN 실패·차단, 승인 요청 횟수
                      ├─ D1  DB   : messages / bots / auth_req 테이블
                      └─ RL       : (선택) 비로그인 요청 속도 제한
                      │
                      └──▶ Telegram Bot API (메인 봇, 추가 봇, 인증 봇)
```

| 파일 | 내용 |
|---|---|
| `src/worker.js` | 서버(API) + 화면(HTML/CSS/JS)이 모두 들어 있는 Worker 코드 |
| `wrangler.jsonc` | Wrangler CLI로 배포할 때 쓰는 설정 예시 |
| `.dev.vars.example` | 로컬 개발용 시크릿 예시 |

D1 테이블은 **첫 요청 때 자동으로 만들어지므로** 직접 SQL을 실행할 필요가 없습니다.

---

## 3. 설치 – 대시보드로 처음부터 만들기

브라우저만으로 설치하는 방법입니다. (PC에 아무것도 설치하지 않아도 됩니다)

### Step 1. 텔레그램 봇 2개 만들기

1. 텔레그램에서 **@BotFather** 를 열고 `/newbot` 을 보냅니다.
2. 봇 이름과 아이디(…bot 으로 끝나야 함)를 입력하면 **API 토큰**(`123456789:AAH...`)을 받습니다.
   → 이것이 **메인 봇** 토큰(`BOT_TOKEN`)입니다.
3. 같은 방법으로 봇을 하나 더 만듭니다.
   → 로그인 승인용 **인증 봇** 토큰(`AUTHBOT_TOKEN`)입니다.
4. 메인 봇을 그룹에서 쓰려면 BotFather에서 `/setprivacy` → 해당 봇 → **Disable** 로 바꾸면 그룹의 모든 메시지를 받을 수 있습니다.
5. 텔레그램에서 **인증 봇을 열고 `/start` 를 한 번 보냅니다.** (봇은 먼저 말을 건 사람에게만 메시지를 보낼 수 있습니다)

### Step 2. 내 텔레그램 사용자 ID 확인

- 메인 봇에게 아무 메시지나 보낸 뒤 웹앱에서 🔄 를 누르면 대화방 제목 옆 괄호에 숫자 ID가 보입니다.
- 또는 텔레그램의 `@userinfobot` 같은 봇으로 확인할 수 있습니다.
- 이 숫자가 `AUTH_CHAT_ID` 입니다.

### Step 3. KV 네임스페이스 만들기

1. Cloudflare 대시보드 → **Storage & databases → Workers KV** → **Create a KV namespace**
2. 이름 예: `memo-bans` → Create

### Step 4. D1 데이터베이스 만들기

1. **Storage & databases → D1 SQLite Database** → **Create Database**
2. 이름 예: `memo-db` → Create (테이블은 만들 필요 없음)

### Step 5. Worker 만들고 코드 붙여넣기

1. **Compute → Workers & Pages** → **Create** → **Start with Hello World!** → 이름 `memo` 로 생성
2. **Edit code** 를 눌러 편집기를 엽니다.
3. 기존 코드를 모두 지우고 이 저장소의 `src/worker.js` 내용을 **전부 붙여넣습니다.**
4. 오른쪽 위 **Deploy** 를 누릅니다.

### Step 6. 바인딩 연결 (Settings → Bindings → Add binding)

| 종류 | 변수 이름 | 선택할 리소스 |
|---|---|---|
| KV namespace | `BANS` | Step 3의 `memo-bans` |
| D1 database | `DB` | Step 4의 `memo-db` |
| Rate limiter (선택) | `RL` | 원하는 한도로 생성 |

### Step 7. 시크릿·변수 등록 (Settings → Variables and Secrets → Add variable)

| 이름 | 종류 | 값 예시 | 필수 |
|---|---|---|---|
| `BOT_TOKEN` | Secret | 메인 봇 토큰 | ✅ |
| `PIN` | Secret | `1234` 처럼 원하는 숫자 | ✅ |
| `AUTHBOT_TOKEN` | Secret | 인증 봇 토큰 | 승인 로그인 사용 시 |
| `AUTH_CHAT_ID` | Variable | Step 2의 내 사용자 ID | 승인 로그인 사용 시 |
| `ONETIME_SESSION_SEC` | Variable | `60` | 선택 (기본 120) |
| `KEEP_PER_CHAT` | Variable | `20` | 선택 (기본 20) |
| `SESSION_SECRET` | Secret | 긴 임의 문자열 | 선택 (아래 9장 참고) |

> 시크릿/변수를 저장하면 자동으로 다시 배포되어 바로 적용됩니다.

### Step 8. 접속

- `https://memo.<내 서브도메인>.workers.dev` 를 열고 PIN을 입력하면 됩니다.
- (선택) **Settings → Domains & Routes** 에서 **Preview URLs** 를 켜 두면 배포 전 테스트 주소를 쓸 수 있습니다.

---

## 4. 설치 – Wrangler CLI로 배포하기 (선택)

PC에서 코드로 관리하고 싶을 때의 방법입니다. Node.js 18 이상이 필요합니다.

```bash
# 1) 저장소 받기
git clone https://github.com/<내 아이디>/memo.git
cd memo

# 2) Cloudflare 로그인
npx wrangler login

# 3) KV, D1 만들기 → 출력되는 ID를 wrangler.jsonc 의 <...> 자리에 붙여넣기
npx wrangler kv namespace create memo-bans
npx wrangler d1 create memo-db

# 4) wrangler.jsonc 의 AUTH_CHAT_ID 를 내 텔레그램 사용자 ID로 수정

# 5) 시크릿 등록 (값은 입력 프롬프트에서 넣음)
npx wrangler secret put BOT_TOKEN
npx wrangler secret put PIN
npx wrangler secret put AUTHBOT_TOKEN

# 6) 배포
npx wrangler deploy
```

로컬 테스트: `.dev.vars.example` 을 `.dev.vars` 로 복사해 값을 채운 뒤 `npx wrangler dev`

> ⚠ 대시보드와 Wrangler를 섞어 쓰면, `wrangler deploy` 시 `wrangler.jsonc` 의 변수 값이 대시보드 값을 덮어씁니다. 한쪽으로 정해서 관리하세요.

---

## 5. 사용법

### 5-1. 로그인

| 방법 | 순서 | 세션 |
|---|---|---|
| **PIN** | PIN 입력 → 입장 | 12시간, 모든 기록 표시 |
| **텔레그램 승인** | **📱 인증요청** → 텔레그램에 온 메시지에서 확인 코드를 확인하고 **✅ 허가하기** | `ONETIME_SESSION_SEC` 초, 새 메시지만 표시 |

- 승인 요청 메시지에는 확인 코드·IP·브라우저·시각이 표시됩니다. **화면의 코드와 같을 때만** 허가하세요.
- 승인 세션에서는 왼쪽 아래에 `⏱ 임시 세션 · 남은 시간` 이 표시되고, 시간이 끝나면 로그인 화면으로 돌아갑니다.

### 5-2. 메시지 확인·보내기

1. 왼쪽 위 탭에서 봇을 고릅니다. (‹ › 버튼, 마우스 휠로 이동)
2. **🔄 새 메시지 확인** 을 누르면 텔레그램에서 새 메시지를 가져옵니다.
   - 여러 브라우저가 동시에 가져오면 충돌하므로 **자동 확인은 하지 않습니다.**
3. 대화방을 고르고 아래 입력창에 입력합니다.
   - 기본: **Enter 전송 / Shift+Enter 줄바꿈**
   - **⤢ 확장 버튼**: 입력창이 크게 열리고 **Enter 줄바꿈 / Ctrl+Enter 전송**
4. 📁 버튼, 끌어다 놓기, 붙여넣기로 파일을 보냅니다. 입력창의 글은 파일 설명(캡션)이 됩니다.
5. 📁 옆 **이미지 전송 방식** 버튼으로 이미지 전송 방법을 고릅니다. (선택은 브라우저에 저장)

   | 버튼 | 방식 | 결과 |
   |---|---|---|
   | 🖼️ (회색, 기본) | `sendPhoto` | 사진으로 표시, 텔레그램이 해상도를 줄이고 압축 |
   | 💾 (파란색) | `sendDocument` | 파일로 전송, 원본 화질 그대로 |

   - 사진 모드에서도 JPEG·PNG·WEBP 이고 10MB 이하일 때만 사진으로 보내고, 그 외(GIF·BMP 등)는 항상 파일로 보냅니다.
   - 사진 전송이 실패하면 자동으로 파일로 다시 보냅니다.

### 5-3. 메시지 복사·삭제

- 메시지에 마우스를 올리면 **복사(겹친 사각형)** 와 **✕(삭제)** 아이콘이 나타납니다. (모바일은 항상 표시)
- 헤더의 **🗑** 은 해당 대화방 기록 전체 삭제입니다.
- 삭제는 **서버(D1)와 브라우저 기록**에서만 지워지며, 텔레그램의 실제 메시지는 그대로입니다.

### 5-4. 봇 추가·제거

1. 탭 줄 끝의 **＋** → @BotFather 에서 받은 토큰 입력 → 추가
2. 탭의 **×** 를 누르면 제거됩니다. (그 봇의 서버 기록도 삭제, 텔레그램의 봇 자체는 그대로)
- 첫 번째 ★ 탭은 `BOT_TOKEN` 의 기본 봇으로 제거할 수 없습니다.
- 웹훅(webhook)이 설정된 봇은 getUpdates를 쓸 수 없어 메시지를 받지 못합니다.

---

## 6. 설정값 정리

| 이름 | 설명 | 범위 / 기본값 |
|---|---|---|
| `KEEP_PER_CHAT` | 봇·대화방마다 서버에 남길 메시지 수. 넘치면 오래된 것부터 삭제 | 1~1000 / 20 |
| `ONETIME_SESSION_SEC` | 승인 로그인의 승인 대기 시간 = 세션 유지 시간(초) | 10~86400 / 120 |
| `AUTH_CHAT_ID` | [허가하기]를 누를 수 있는 텔레그램 사용자 ID | – |

- 변수 값은 대시보드에서 바꾸면 **저장과 동시에 바로 적용**됩니다.
- 이미 로그인된 세션의 만료 시간은 로그인할 때 정해진 값 그대로 유지됩니다.

코드 안의 고정값 (`src/worker.js` 상단)

| 상수 | 값 | 설명 |
|---|---|---|
| `SESSION_TTL` | 12시간 | PIN 세션 유지 시간 |
| `MAX_FAIL` / `BAN_SEC` | 5회 / 1시간 | PIN 실패 시 차단 |
| `RPM_ANON` / `RPM_AUTH` | 60 / 300 | IP당 분당 요청 수 제한 |
| `MAX_UP` | 50MB | 업로드 한도 (텔레그램 봇 API 한도) |

---

## 7. 코드 수정·배포 방법 (미리보기 → 배포)

운영 중인 사이트를 바로 바꾸지 않고 **먼저 테스트한 뒤 배포**하는 순서입니다.

1. Worker → **Edit code** 에서 코드를 수정합니다.
2. 오른쪽 위 **Deploy 옆 ▼** → **Save** 선택 → **Save** 버튼 → 메시지 입력 후 저장
   - 새 버전만 만들어지고 실제 사이트는 바뀌지 않습니다.
3. **Deployments** 탭에서 새 버전 ID(예: `d73a74bc`)를 확인합니다.
4. 미리보기 주소 `https://<버전ID>-memo.<서브도메인>.workers.dev` 에서 테스트합니다.
   - 주소가 다르므로 로그인은 따로 해야 합니다. (봇·DB·변수는 공유)
5. 문제가 없으면 Deployments 에서 해당 버전의 **⋯ → Promote version** 으로 배포합니다.
6. 문제가 생기면 이전 버전을 **Promote version** 하면 즉시 롤백됩니다.

수정한 코드는 이 저장소의 `src/worker.js` 에도 반영(commit)해 두세요.

> 💡 `src/worker.js` 의 HTML 부분(`APP_HTML`, `LOGIN_HTML`)은 템플릿 문자열(백틱)입니다.
> 안에서 백틱(`` ` ``)과 `${`를 쓰지 말고, 줄바꿈 문자는 `'\\n'` 처럼 역슬래시를 두 번 써야 합니다.

---

## 8. API 목록

| 경로 | 메서드 | 로그인 | 설명 |
|---|---|---|---|
| `/` | GET | – | 로그인 안 됨: 로그인 화면 / 로그인: 앱 화면 |
| `/api/login` | POST | – | PIN 로그인 |
| `/api/auth/request` | POST | – | 텔레그램 승인 요청 보내기 |
| `/api/auth/status?id=` | GET | – | 승인 결과 확인 (승인 시 임시 세션 쿠키 발급) |
| `/api/authhook` | POST | 텔레그램 | 인증 봇 웹훅 (시크릿 헤더로 검증) |
| `/api/logout` | POST | ✅ | 로그아웃 |
| `/api/me` | GET | ✅ | 기본 봇 정보 |
| `/api/bots` | GET | ✅ | 봇 목록, 저장 개수, 세션 종류 |
| `/api/bots/add` · `/api/bots/remove` | POST | ✅ | 봇 추가·제거 |
| `/api/updates?bot=&offset=` | GET | ✅ | 새 메시지 가져오기 (getUpdates) |
| `/api/send` | POST | ✅ | 텍스트 전송 |
| `/api/upload?bot=&chat_id=&kind=` | POST | ✅ | 파일 업로드 (스트리밍 중계) |
| `/api/file?bot=&id=` | GET | ✅ | 파일 다운로드 (스트리밍 중계) |
| `/api/history?bot=` | GET | ✅ | 서버 저장 기록 (임시 세션은 빈 목록) |
| `/api/delete` | POST | ✅ | 메시지·대화방 기록 삭제 |

D1 테이블

| 테이블 | 내용 |
|---|---|
| `messages` | 봇·대화방별 메시지 (bot, chat_id, message_id, date, data) |
| `bots` | 추가한 봇 (토큰은 AES-GCM 암호화) |
| `auth_req` | 진행 중인 승인 요청 (만료 후 자동 정리) |

---

## 9. 보안

- **비밀값은 코드에 없습니다.** 토큰·PIN은 Worker 시크릿에만 있고, 추가한 봇 토큰도 서버에서 암호화되어 브라우저로 내려가지 않습니다.
- **세션 쿠키**: HttpOnly · Secure · SameSite=Strict, HMAC 서명. 세션 종류(PIN/임시)도 서명에 포함되어 조작할 수 없습니다.
- **CSRF**: 다른 사이트에서 온 POST 요청(Origin 불일치)은 거부합니다.
- **무차별 대입 방지**: PIN 5회 실패 시 1시간 차단, 승인 요청은 IP당 10분에 5회.
- **승인 로그인**: 지정한 텔레그램 계정만 허가 가능, 1회용, 만료 시간 적용, 웹훅은 시크릿 토큰으로 검증.
- **CSP** 와 보안 헤더(nosniff, frame DENY, no-referrer)를 적용합니다.
- `SESSION_SECRET` 이 없으면 서명 키가 `BOT_TOKEN`+`PIN` 에서 만들어집니다.
  - PIN을 바꾸면 기존 세션이 모두 로그아웃됩니다.
  - `SESSION_SECRET` 을 새로 넣거나 바꾸면 모든 세션이 로그아웃되고, **추가한 봇은 다시 등록**해야 합니다(토큰 암호화 키가 바뀌므로).

---

## 10. 문제 해결

| 증상 | 원인 / 해결 |
|---|---|
| "다른 곳에서 확인 중이거나 웹훅이 설정된 봇입니다" | 다른 브라우저가 동시에 확인 중이거나, 그 봇에 웹훅이 설정됨 → 잠시 후 다시, 또는 다른 서비스의 웹훅 해제 |
| 인증요청 시 "텔레그램 전송 실패" | 인증 봇에게 `/start` 를 보내지 않았음, 또는 `AUTH_CHAT_ID` 가 틀림 |
| 인증요청 시 "설정되지 않았습니다" | `AUTHBOT_TOKEN` / `AUTH_CHAT_ID` / D1 바인딩 확인 |
| 20MB 넘는 파일 다운로드 불가 | 텔레그램 봇 API 한도입니다. 텔레그램 앱에서 받으세요. |
| 봇 탭이 안 보이고 목록이 계속 로딩 | D1 바인딩(`DB`) 확인, Worker **Observability → Logs** 에서 오류 확인 |
| 다른 PC에서 기록이 다름 | 서버에는 대화방마다 최근 `KEEP_PER_CHAT` 개만 저장됩니다. |
| Worker 이름(주소)을 바꾼 뒤 | 새 주소에서 다시 로그인. 인증 봇 웹훅은 다음 "인증요청" 때 자동으로 새 주소로 바뀝니다. |

---

## 무료 한도 참고

Workers·KV·D1 모두 무료 플랜에 하루 요청/읽기/쓰기 한도가 있습니다. 개인 사용량이면 충분하지만,
정확한 최신 수치는 Cloudflare 공식 문서(Workers / KV / D1 Pricing)와 대시보드의 사용량 화면에서 확인하세요.
