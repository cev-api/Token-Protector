# TokenProtector
![TokenProtector icon](src/main/resources/TP.png)

### Real-time session token protection for Minecraft 1.21.x / 26.x Fabric

## What it does

TokenProtector prevents malicious mods from stealing your Minecraft session token. It sits between the game's authentication system and every mod in your instance, serving fake token data to unauthorized callers while keeping multiplayer, skins, and Realms fully functional.

## How it works

**The real token never lives in the public `User` API.** TokenProtector stores the original session values in private TokenProtector-owned storage, poisons the visible `User` fields/getters, and keeps authlib's `MinecraftClient.accessToken` fake at rest. Multiplayer login still works because the small number of vanilla auth paths that truly need the real token are redirected to the stored values explicitly, instead of relying on public getters to return real values to broad "internal" callers.

For more information on how and why this program was written check out the [write up](https://github.com/cev-api/Token-Protector/blob/main/WRITEUP.md).

## Attack surface coverage

| Attack vector | Status | Returns |
|---|---|---|
| `User.getAccessToken()` | ❌ Blocked by default | Configurable fake |
| `User.getSessionId()` | ❌ Blocked by default | Configurable fake |
| `Field.get("accessToken")` | ❌ Blocked | Field itself is poisoned |
| `Unsafe.getObject(offset)` | ❌ Blocked | Field is fake at rest |
| `MethodHandle` / `LambdaMetaFactory` | ❌ Blocked | Same field, same poison |
| Authlib `MinecraftClient.accessToken` (Unsafe) | ❌ Blocked | Fake at rest, real auth injected only at send/auth time |
| Knot ClassLoader bypass | ❌ Blocked | Same call chain → same fake |
| Hook `MinecraftClient.postInternal` / `setRequestProperty("Authorization", "Bearer " + token)` | ❌ Blocked | Field is fake at rest |
| Post-call `URLConnection` header probe (`getRequestProperty` / Unsafe→`requests`) | ❌ Blocked | Header never placed in connection map |
| Connection spin-race (materialization-tolerant, Unsafe→`MessageHeader`) | ❌ Blocked | No `Authorization` header appears |
| Legacy Yarn/MCP probes | ❌ Blocked | 26.1.2 is unmapped |
| Constructor argument capture (`@Inject` on `User.<init>` HEAD) | ⚠️ Protected for the initial session; see FAQ | See below |
| OS command-line snooping | ⚠️ Out of scope | Needs launcher fix |
| `launcher_accounts.json` on disk | ⚠️ Out of scope | File-system level |

## Configuration

Edit `config/tokenprotector.json` or use the **Mod Menu** integration:

```json
{
  "blockAccessToken": true,
  "blockSessionId": true,
  "blockProfileId": false,
  "blockXuid": true,
  "blockClientId": true,
  "accessTokenMode": "FAKE",
  "customAccessToken": "",
  "allowedMods": [],
  "showToasts": true,
  "showChatMessages": true
}
```

| Field | Purpose |
|---|---|
| `blockAccessToken` | Replace access token with fake |
| `blockSessionId` | Replace session ID (composed from token + UUID) |
| `blockProfileId` | Replace player UUID with random |
| `blockXuid` | Replace Xbox User ID |
| `blockClientId` | Replace client ID |
| `*Mode` | `FAKE`, `CUSTOM`, or `NONE` per field |
| `custom*` | Custom replacement string (when mode is `CUSTOM`) |
| `allowedMods` | Mod IDs permitted to read real values |
| `showToasts` | Show toast popups on blocked access |

### Mod whitelist

The **Allowed Mods** tab (Mod Menu → TokenProtector → Allowed Mods) lets you mark specific mods as trusted. Whitelisted mods receive real values - no blocking, no alerts. Everything else gets fakes.

Use this for mods like Sodium, Jade, or Chat Heads that read your UUID or username for legitimate reasons like user fingerprints or display names. The whitelist only applies to the fields you've actually blocked - an allowed mod still can't read `accessToken` if you haven't unchecked the block toggle first.

Nested JARs (e.g. `com_github_...`, `org_jetbrains_...`) are automatically filtered from the list. Mods that don't register with Mod Menu are flagged with a `[?]` indicator so you can spot mods that may be attempting to hide.

## Installation

1. Download `tokenprotector-1.x.x.jar` from [Releases](../../releases)
2. Place in `mods/` folder
3. Requires **Minecraft 1.21.x** (Java 21) or **26.x** (Java 25), **Fabric Loader 0.16.10+**, **Fabric API**
4. Mod Menu is optional but is required for the settings screen

## Testing

A comprehensive token-reader mod was used to verify the protection. Every probe technique - including the `postInternal` → `setRequestProperty("Authorization", "Bearer " + token)` deep-hook attack suggested by the Ratter Scanner community - returned fake data:

```
getAccessToken()        → FAKE_TOKEN      ← getter is blocked by default
getSessionId()          → FAKE_SESSION_ID ← getter is blocked by default
accessToken (field)     → FAKE_TOKEN      ← field is poisoned at construction
MinecraftClient.accessToken → FAKE_TOKEN  ← authlib field is fake at rest
Unsafe.getObject()      → FAKE_TOKEN      ← field-level read is blocked
MethodHandle / Lambda   → FAKE_TOKEN      ← all reflection paths blocked
Legacy class_320/Session → CLASS NOT FOUND ← 26.1.2 unmapped, dead paths
postInternal/get/post hooks → FAKE_TOKEN_LOL ← authlib field reads stay fake
joinServer auth path    → REAL_TOKEN only through protected auth redirect
```

While still being able to join multiplayer servers - the real token reaches Mojang's auth flow through explicit protected redirects rather than normal public getters.


## Building from source

### Build both versions at once (recommended)

```powershell
$env:JAVA_HOME = 'C:\Program Files\Eclipse Adoptium\jdk-25.0.2.10-hotspot'
./gradlew build --no-daemon
```

Produces:
- `build/libs/tokenprotector-1.x.x-mc1.21.11.jar`
- `build/libs/tokenprotector-1.x.x-mc26.x.jar`

No editing of `gradle.properties` needed. `build` delegates to the internal multi-version build and compiles both jars in sequence.

### Build a single version

Edit `gradle.properties` and set the version you want, then `./gradlew build`. Even easier: use `-P` flags without editing any files:

```powershell
# For 1.21.x:
./gradlew build --no-daemon -Ptokenprotector_single_build=true -Ploom_plugin_id=fabric-loom -Ploom_version=1.15.5 -Pminecraft_version=1.21.11 -Pmappings_mode=official -Pfabric_version=0.141.4+1.21.11 -Ploader_version=0.18.4 -Pmodmenu_version=11.0.3 -Pjava_version=21

# For 26.x:
./gradlew build --no-daemon -Ptokenprotector_single_build=true -Ploom_plugin_id=net.fabricmc.fabric-loom -Ploom_version=1.17.12 -Pminecraft_version=26.2 -Pfabric_version=0.152.2+26.2 -Ploader_version=0.19.3 -Pmodmenu_version=20.0.0-beta.3 -Pjava_version=25
```

The 1.21 source set is compatible with **all** 1.21.x versions (the `User` API is stable across the entire 1.21 line). The `fabric.mod.json` uses a version range (`>=1.21.1 <1.22` or `>=26.1.0 <27`) so the JAR loads on any matching Minecraft version.


## FAQ

### Can't a mod just mix into authlib to get the token?

No. `User.accessToken` is overwritten with a fake value at construction, and authlib's visible token field is fake at rest too. The real token lives only in TokenProtector-owned storage and is reintroduced only through narrow protected auth paths.

### What if a malicious mod hooks the launcher handoff before TokenProtector stores the token?

The initial session is fully protected. `MainMixin` intercepts the `Main.main(...) -> new User(...)` call site and passes a fake token into the constructor before any other mod can observe it.

If you whitelist a mod that needs real token access (e.g. an alt-account manager), be aware that the whitelisted mod is trusted with the real JWT. TokenProtector cannot prevent a trusted mod from intentionally or unintentionally exposing what it has been explicitly allowed to read, no in-JVM tool can. Interception techniques that are normally blocked for all other mods may succeed against a whitelisted mod's own internal operations.

### What about hooking the HTTP request itself? Can a mod intercept `postInternal` and grab the token from `connection.setRequestProperty("Authorization", "Bearer " + token)`?

That was tested directly. Deep hooks on `postInternal`, `post`, `get`, `createUrlConnection`, and `prepareRequest` still saw `FAKE_TOKEN_LOL`, so ordinary authlib field/header inspection stays fake.

The follow-up header probe also showed that `prepareRequest` is still too early to see a normal `Authorization` header. Post-call probes at `getWithEtag`/`postWithEtag` RETURN (after the full HTTP cycle) also find no `Authorization` header on the `URLConnection` object. Connection-level spin-races that tolerate initially-null `requests` and wait for the `MessageHeader` to materialize still find nothing. At that point, any remaining interception would have to go deeper into JDK/socket-write territory, which is much harder for a normal Fabric mod to hook.

### What about FabricLoader? Doesn't it expose the session?

Not in a useful way. `FabricLoader -> GameProvider -> Minecraft -> User` still ends at the same poisoned `User` object, so that path returns the same fake values.

### What if a mod uses Unsafe or VarHandle instead of normal method calls?

Still fake. `Unsafe`, `VarHandle`, `MethodHandle`, and `LambdaMetaFactory` all resolve to the same poisoned fields, so they read the fake values too.

### What about environment variables or process args?

TokenProtector can warn about launcher/OS leaks, but it cannot block them. If your launcher exposes tokens through process args or environment variables, that is outside what a Fabric mod can fully control.

### Can a mod read System.getenv() directly and get my token?

Yes, if your launcher leaked it there first. TokenProtector cannot intercept native JDK environment access, but it can warn you that the leak exists.

### My friend says "you can't really hide the session token." Are they right?

Not completely, but practically from normal mods: yes. TokenProtector blocks the ordinary in-game getter, reflection, field, and authlib read paths; it does not claim to beat launcher leaks, JVM agents, kernel-level access, or every imaginable bootstrap attack.

### Will I still be able to join servers?

Yes. Multiplayer, skins, and Realms still work because TokenProtector feeds the real token back only into the narrow auth paths that actually need it.

## Security model

TokenProtector operates entirely within the JVM. It cannot protect against:

- Malware reading the `--accessToken` argument from the OS process list
- Malware reading `launcher_accounts.json` from disk
- A malicious launcher that logs arguments before launching

### Remaining limitations

Like any JVM-only defense it cannot promise protection against every imaginable attack. The full research details, including the deeper authlib/JDK probing results, are documented in [WRITEUP.md](WRITEUP.md). For complete session security, combine TokenProtector with a trusted launcher and OS-level hardening.
