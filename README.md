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
| Retransformation targeting a single shared gate helper (`authorized()`) | No such helper exists (read gate is inline and duplicated) |

TokenProtector sanitizes Fabric's retained launch arguments during Fabric `preLaunch`. Fabric builds the later `Main.main(String[])` array from this retained data. As a result, the game receives the replacement token before normal Minecraft startup code runs.

TokenProtector also defends the internal state that holds the real token for authentication. The credential is never kept as a plaintext String: it is masked against a per-capture random pad and the plaintext is materialised only inside the gated read path at the moment it is handed to an authentication call. The read gate is performed inline in the accessor rather than delegated to a single helper method, so there is no `authorized()`-style choke point that a hostile retransformation could force to always allow.

## Adversarial testing

TokenProtector is tested against TokenReader, a separate adversarial Fabric test mod (100+ probes across 13 categories). Every probe receives replacement data or nothing, and Minecraft authentication still completes:

- normal, reflective, obfuscated, and low-level reads of protected fields and getters → `FAKE_TOKEN_LOL`
- maximum-priority (`Integer.MAX_VALUE`) Mixins on `Main.main` and `User` construction → `FAKE_TOKEN_LOL`
- self-attached Byte Buddy agent advice at the first bytecode of `Main.main` → `FAKE_TOKEN_LOL` (preLaunch scrubs retained arguments first)
- tested authlib request hooks and returned connections → replacement data, no `Authorization` value
- authlib internals via `Unsafe`, reflection, and `privateLookupIn` → `FAKE_TOKEN_LOL`
- 15-second token-field race (543,484,520 reads) and 10-second connection race (48,771,570 reads) → no real token
- anti-protector vault read (`getDeclaredField("accessToken")`) → no such field (masked at rest)
- anti-protector agent gate-kill retransformation → no `authorized()` helper to neutralise; reflective `forAuthentication()` still returns `null`

Full details and technical limits are in [WRITEUP.md](WRITEUP.md).

## Limits

TokenProtector is a hardening mod, not a sandbox. Its limitations:

- all mods share one JVM, and the real token must still exist in the process for Minecraft to authenticate, so absolute secrecy is impossible
- the retained credential is masked at rest, but an adaptive reflective/`Unsafe` attacker can still decode the mask
- code that runs outside TokenProtector's own hooks is out of reach: a launcher-supplied `-javaagent`, a modified loader/JVM, an earlier `preLaunch` that copies the retained arguments, and agent retransformation of TokenProtector's own methods
- native code, OS/launcher/file copies of the token, and network interception outside the tested Java paths cannot be stopped in-JVM
- direct memory reads and some low-level access paths bypass caller-aware hooks, so not every read is attributable

While these are the limitations, most are still detected by the mod, just not blocked. This is because blocking them is outside what a same-JVM Fabric mod can enforce. Competing high-priority Mixins, `preLaunch` entrypoints, agent tooling, dynamic-attach artifacts, stripped protected classes, spin-races, and unexpected credential copies in environment variables, system properties, or process arguments all raise alerts. Only events that give no in-JVM signal at all, such as a launcher agent that runs before Fabric, native code, file copies, and network interception cannot be surfaced, and those are the true silent limits.

Full technical detail is in [WRITEUP.md](WRITEUP.md).

## Alerts

TokenProtector reports blocked caller-aware access (mod, class, method, line, field) and alerts on what it cannot block:

- blocked reads return replacement data and raise an alert with caller details
- high-speed polling / spin-race detection alerts even for whitelisted mods
- OS-level leaks (environment variables, system properties, process arguments) are detected and reported, not blocked
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
