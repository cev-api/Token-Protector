# TokenProtector

![TokenProtector icon](src/main/resources/TP.png)

### Session token protection for Minecraft Fabric

TokenProtector is a client-side security mod for Minecraft 1.21.x and 26.x.

It reduces Minecraft access-token exposure to other Fabric mods. It replaces exposed token values with replacement data and reports blocked access when it can identify the caller.

Normal multiplayer, skins, and Realms continue to work because TokenProtector keeps the real access token only for the Minecraft authentication path that needs it.

## What TokenProtector protects

TokenProtector protects these tested in-JVM paths:

| Path | Tested result |
|---|---|
| `User.getAccessToken()` and `User.getSessionId()` | Replacement value |
| Direct `User.accessToken` field reads | Replacement value |
| Protected `User` and authlib fields read with reflection, `Unsafe`, `VarHandle`, or `MethodHandle` | Replacement value or access denied |
| `User` constructor HEAD capture | Replacement value |
| Maximum-priority `User` constructor Mixin | Replacement value |
| `MinecraftClient.accessToken` | Replacement value at rest |
| `FabricLoader.getLaunchArguments(false)` | Replacement `accessToken` |
| `FabricLoader.getLaunchArguments(true)` | Access token omitted |
| Tested authlib request hooks | Replacement value |
| High-speed token-field polling | Replacement value for the full test |
| Java-agent advice at raw `Main.main` bytecode entry | Replacement value |
| Tested `HttpURLConnection` auth-header probes | No `Authorization` value observed |
| Reflective read of the internal vault field (`getDeclaredField("accessToken")`) | No such field exists (credential is masked at rest) |
| Blind scan of static String fields for a JWT | No real token found |
| Native memory reads through a supported scanner hook | Token recovery confirmed and attributed to the reading mod; alerted, not blocked |
| Retransformation targeting a single shared gate helper (`authorized()`) | No such helper exists (read gate is inline and duplicated) |

TokenProtector sanitizes Fabric's retained launch arguments during Fabric `preLaunch`. Fabric builds the later `Main.main(String[])` array from this retained data. As a result, the game receives the replacement token before normal Minecraft startup code runs.

TokenProtector also hardens the internal state that holds the real token for authentication. The retained vault value is masked against a per-capture random pad. Authorized getter and authentication reads still create plaintext Strings, while blocked getters choose replacements before decoding. The read gate is performed inline in the accessor rather than delegated to a single helper method, so there is no `authorized()`-style choke point that a hostile retransformation could force to always allow. Neither masking nor this gate provides process-memory isolation.

## Adversarial testing

TokenProtector is tested against TokenReader, a separate adversarial Fabric test mod (100+ probes across 13 categories). The tested Java-level reads receive replacement data or nothing while Minecraft authentication continues to work:

- normal, reflective, obfuscated, and low-level reads of protected fields and getters → `FAKE_TOKEN_LOL`
- maximum-priority (`Integer.MAX_VALUE`) Mixins on `Main.main` and `User` construction → `FAKE_TOKEN_LOL`
- self-attached Byte Buddy agent advice at the first bytecode of `Main.main` → `FAKE_TOKEN_LOL` (preLaunch scrubs retained arguments first)
- tested authlib request hooks and returned connections → replacement data, no `Authorization` value
- authlib internals via `Unsafe`, reflection, and `privateLookupIn` → `FAKE_TOKEN_LOL`
- 15-second token-field race (543,484,520 reads) and 10-second connection race (48,771,570 reads) → no real token
- anti-protector vault read (`getDeclaredField("accessToken")`) → no such field (masked at rest)
- anti-protector agent gate-kill retransformation → no `authorized()` helper to neutralise; reflective `forAuthentication()` still returns `null`

The native memory scanner path is treated differently, because it cannot be blocked: the read succeeds, and TokenProtector confirms and attributes the recovery. See [Memory reads](#memory-reads).

Full details and technical limits are in [WRITEUP.md](WRITEUP.md).

### Memory reads

The real token has to exist in the Minecraft process memory for the client to authenticate, and another mod that shares that process can copy it out with native code. No Fabric mod can block that read, and TokenProtector does not claim to. What it does provide is detection and attribution on the scanner paths it knows about:

- at capture time TokenProtector stores a SHA-256 fingerprint of the real token (digest, short prefix, and length) instead of the token itself, so detection does not add another full plaintext copy to memory
- when a supported native scanner copies a memory region, TokenProtector inspects the bytes it just read, matching plain 8-bit and UTF-16LE layouts at any offset
- a match proves the scanner's buffer contains the current session token; TokenProtector raises a `SESSION TOKEN RECOVERED FROM MEMORY` alert naming the reading mod (mod name, mod ID, reader class, and scan address) and records it in Recent Detections and `tokenprotector.log`, without logging the token
- a scan window that does not contain the token still raises a lower-severity `NATIVE MEMORY SCAN OBSERVED` notice
- if a known reader is installed but its hook could not be inserted, TokenProtector reports `Memory Read Detector Unavailable` rather than appearing to be covered

Detection is limited to the scanner hooks TokenProtector supports (the path used by the adversarial TokenReader test mod). It is not a universal native-read interceptor, so another scanner, arbitrary native reads, or a reader using a different entry point are not observed. A match also confirms recovery, not live validity, exfiltration, or which process the bytes came from.

Between hookable reads, TokenProtector also shrinks the amount of plaintext available to a scanner: blocked getter paths choose their replacement before any plaintext is decoded, the masking path avoids an extra `char[]` copy of the token, and the decode buffer is zeroed after the plaintext is materialised. That is best-effort hygiene, not a process-memory boundary.

## Limits

TokenProtector is a hardening mod, not a sandbox. Its limitations:

- all mods share one JVM, and the real token must still exist in the process for Minecraft to authenticate, so absolute secrecy is impossible
- the retained credential is masked at rest, but an adaptive reflective/`Unsafe` attacker can still decode the mask
- code that runs outside TokenProtector's own hooks is out of reach: a launcher-supplied `-javaagent`, a modified loader/JVM, an earlier `preLaunch` that copies the retained arguments, and agent retransformation of TokenProtector's own methods
- native code, OS/launcher/file copies of the token, and network interception outside the tested Java paths cannot be stopped in-JVM
- direct memory reads and some low-level access paths bypass caller-aware hooks, so not every read is attributable, and a read that is detected is reported, not stopped

Competing Mixins, early entrypoints, agent tooling, spin-races, and unexpected credential copies raise alerts. Native token recovery is detectable and attributable only through supported scanner hooks, where it is confirmed but not blocked; unobserved native and external reads can remain silent.

Full technical detail is in [WRITEUP.md](WRITEUP.md).

## Alerts

TokenProtector reports blocked caller-aware access (mod, class, method, line, field) and alerts on what it cannot block:

- blocked reads return replacement data and raise an alert with caller details
- high-speed polling / spin-race detection alerts even for whitelisted mods
- OS-level leaks (environment variables, system properties, process arguments) are detected and reported, not blocked
- native memory scans on supported scanner hooks are detected and attributed to the reading mod, reported as confirmed token recovery when the token is present in the read window
- posture findings (competing high-priority Mixins, preLaunch entrypoints, agent tooling, dynamic-attach artifacts, stripped protected classes) are surfaced as alerts

A warning means a possible credential is present in an inspected source; it does not prove another mod reads it. A single normal `--accessToken` launch argument is treated as expected exposure; warnings are for unexpected copies (duplicate tokens, `--msaToken`/`--refreshToken`, unknown JWT-shaped or wrapper-embedded values, long credential-like values, env/system-property leaks).

TokenProtector cannot rewrite the native OS command line, launcher files, launcher logs, or another process, and reports scans as incomplete when Java hides process data.

### Log history

Every TokenProtector console line (INFO, WARN, ERROR, and ALERT) is recorded twice so it is never lost when the launcher console scrolls or closes:

- the Mod Menu "Recent Detections" tab shows the complete in-game log for the current session, newest first, with no entry cap and no truncation (long lines wrap); and
- `tokenprotector.log` in the Minecraft game directory appends every line across sessions as a separate on-disk archive.

Only ALERT lines increase the unread count shown on the top-right banner; INFO and WARN lines still appear in the in-game history and in the file.

## Optional JVM hardening

Users who want to block the dynamic self-attach route used by tools such as Byte Buddy can add this JVM argument in the launcher:

```text
-XX:+DisableAttachMechanism
```

This option must be present when Java starts. TokenProtector cannot enable it after the JVM starts.

It disables the JVM Attach mechanism used by dynamic self-attach. It does not stop a launcher-supplied `-javaagent`, native instrumentation, or a modified JVM or loader.

## Configuration

Use Mod Menu or edit `config/tokenprotector.json`.

| Setting | Function |
|---|---|
| `blockAccessToken` | Replace the access token |
| `blockSessionId` | Replace the session ID |
| `blockProfileId` | Replace the player UUID |
| `blockXuid` | Replace the Xbox user ID |
| `blockClientId` | Replace the client ID |
| `*Mode` | Use `FAKE`, `CUSTOM`, or `NONE` |
| `custom*` | Set a custom replacement value |
| `allowedMods` | Allow selected caller-aware getter access |
| `showToasts` | Show protection alerts |
| `showChatMessages` | Show protection messages in chat |

Only allow a mod when you trust it. An allowed caller-aware path can return real data to that mod.

## Installation

1. Download the correct TokenProtector JAR from [Releases](../../releases).
2. Put the JAR in the Minecraft `mods/` folder.
3. Install Fabric API.
4. Install Mod Menu if you want the settings screen.

Tested build targets:

- Minecraft 1.21.11, Java 21, Fabric Loader 0.18.4
- Minecraft 26.2, Java 25, Fabric Loader 0.19.3

## Build from source

Build both targets:

```powershell
./gradlew build --no-daemon
```

Output:

```text
build/libs/tokenprotector-1.x.x-mc1.21.11.jar
build/libs/tokenprotector-1.x.x-mc26.x.jar
```

For the technical design, adversarial test methods, and security limits, see [WRITEUP.md](WRITEUP.md).
