# TokenProtector
![TokenProtector icon](src/main/resources/TP.png)

### Real-time session token protection for Minecraft 1.21.x / 26.x Fabric

## What it does

TokenProtector reduces exposure through common in-game session-token read paths. On the paths it covers, it serves fake token data to unauthorized callers while keeping multiplayer, skins, and Realms functional. It is not a security boundary against a malicious mod running in the same JVM.

## How it works

The real token does not live in the public `User` API on the covered paths. TokenProtector holds it internally rather than in a public mutable token stash or public-facing vault data, poisons visible `User` fields/getters, and keeps authlib's `MinecraftClient.accessToken` fake at rest. Multiplayer login works because the vanilla auth paths redirected by the mod obtain the token explicitly. This is hardening, not isolation: a determined mod in the same JVM can target, cancel, outrank, or run before these hooks.

For more information on how and why this program was written check out the [write up](https://github.com/cev-api/Token-Protector/blob/main/WRITEUP.md).

## Attack surface coverage

The statuses below describe regression-tested probe paths with protection enabled and the test mod unwhitelisted. They are not a guarantee against a deliberately targeting mod, mixin cancellation/priority changes, earlier bootstrap code, JVM agents, launchers, disk credential files, or other external paths.


| Attack vector | Status | Returns |
|---|---|---|
| `User.getAccessToken()` | Tested: fake result | Configurable fake |
| `User.getSessionId()` | Tested: fake result | Configurable fake |
| `Field.get("accessToken")` | Tested: fake result | Field itself is poisoned |
| `Unsafe.getObject(offset)` | Tested: fake result | Field is fake at rest |
| `MethodHandle` / `LambdaMetaFactory` | Tested: fake result | Same field, same poison |
| Authlib `MinecraftClient.accessToken` (Unsafe) | Tested: fake result | Fake at rest; real authentication is redirected |
| Knot ClassLoader bypass | Tested: fake result | Same call chain -> same fake |
| Hook `MinecraftClient.postInternal` / `setRequestProperty("Authorization", "Bearer " + token)` | Tested: fake result | Covered probe sees a fake; not a general egress guarantee |
| Post-call `URLConnection` header probe (`getRequestProperty` / Unsafe -> `requests`) | Tested: fake result | Header not observed by this probe |
| Connection spin-race (materialization-tolerant, Unsafe -> `MessageHeader`) | Tested: fake result | Header not observed by this probe |
| Legacy Yarn/MCP probes | Tested: fake result | 26.1.2 is unmapped |
| Constructor argument capture (`@Inject` on `User.<init>` HEAD) | Mitigated at the covered boundary; see FAQ | See below |
| OS command-line snooping | Out of scope | Needs launcher fix |
| `launcher_accounts.json` on disk | Out of scope | File-system level |

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

The **Allowed Mods** tab (Mod Menu -> TokenProtector -> Allowed Mods) lets you mark specific mods as trusted. Whitelisted mods receive real values - no blocking, no alerts. Everything else gets fakes on covered paths. Whitelisting is an explicit trust decision: a whitelisted mod can receive the real credential.

Use this for mods like Sodium, Jade, or Chat Heads that read your UUID or username for legitimate reasons like user fingerprints or display names. The whitelist only applies to the fields you've actually blocked - an allowed mod still can't read `accessToken` if you haven't unchecked the block toggle first.

Nested JARs (e.g. `com_github_...`, `org_jetbrains_...`) are automatically filtered from the list. Mods that don't register with Mod Menu are flagged with a `[?]` indicator so you can spot mods that may be attempting to hide.

## Installation

1. Download `tokenprotector-1.x.x.jar` from [Releases](../../releases)
2. Place in `mods/` folder
3. Requires **Minecraft 1.21.x** (Java 21) or **26.x** (Java 25), **Fabric Loader 0.16.10+**, **Fabric API**
4. Mod Menu is optional but is required for the settings screen

## Testing

A comprehensive token-reader mod was used for regression testing. The supported probes returned fake data with protection enabled and the test mod unwhitelisted. The listed techniques - including the `postInternal` -> `setRequestProperty("Authorization", "Bearer " + token)` deep-hook attack suggested by the Ratter Scanner community - returned fake data:

```
getAccessToken()              -> FAKE_TOKEN       (covered getter probe)
getSessionId()                -> FAKE_SESSION_ID  (covered getter probe)
accessToken (field)           -> FAKE_TOKEN       (field poisoned at construction)
MinecraftClient.accessToken   -> FAKE_TOKEN       (fake at rest)
Unsafe.getObject()            -> FAKE_TOKEN       (covered field-read probe)
MethodHandle / Lambda         -> FAKE_TOKEN       (covered reflection probe)
Legacy class_320/Session      -> CLASS NOT FOUND  (26.1.2 unmapped path)
postInternal/get/post hooks   -> FAKE_TOKEN_LOL   (covered authlib probes)
joinServer auth path          -> REAL_TOKEN only through redirected authentication
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

A normal authlib read of `User.accessToken` or its backing field sees a fake, and authlib's visible token field is fake at rest. A deliberately targeted mixin, transformer, or earlier hook may still reach a different source or interfere with TokenProtector.

### What if a malicious mod hooks the launcher handoff before TokenProtector stores the token?

The covered `Main.main(...) -> new User(...)` boundary passes a fake token into the constructor. Code that runs earlier, cancels that mixin, or modifies transformation order can evade this protection.

If you whitelist a mod that needs real token access (e.g. an alt-account manager), be aware that the whitelisted mod is trusted with the real JWT. TokenProtector cannot prevent a trusted mod from intentionally or unintentionally exposing what it has been explicitly allowed to read, no in-JVM tool can. Interception techniques that are normally blocked for all other mods may succeed against a whitelisted mod's own internal operations.

### Can another mod interfere with TokenProtector or run before it?

On TokenProtector's covered paths, the Token Reader regression tests were recognised as unauthorised and received fake token data, including the tested constructor/startup probes. However, Fabric mods share a JVM and transformation environment: a sufficiently deliberate mod may cancel or outrank a mixin, transform a class earlier, use an agent, or hook a different path. With enough effort and a targeted implementation, it may be possible to run earlier and steal the real token. TokenProtector reduces exposure to the common tested paths; it cannot guarantee prevention of every same-JVM bypass.

### Would randomising internal class or field names on each launch prevent targeted hooks?

No. It may frustrate a simple static signature, but a mod in the same JVM can inspect loaded classes, transform bytecode, follow data flow, or hook a public/authentication boundary instead. The token must remain available to the redirected login path, so changing an internal name is obscurity rather than a security boundary. TokenProtector instead avoids public mutable token storage and keeps public-facing values fake on its covered paths.

### What about hooking the HTTP request itself? Can a mod intercept `postInternal` and grab the token from `connection.setRequestProperty("Authorization", "Bearer " + token)`?

The included regression probes were tested directly. Deep hooks on `postInternal`, `post`, `get`, `createUrlConnection`, and `prepareRequest` still saw `FAKE_TOKEN_LOL`, so ordinary authlib field/header inspection stays fake.

The follow-up header probe also showed that `prepareRequest` is still too early to see a normal `Authorization` header. Post-call probes at `getWithEtag`/`postWithEtag` RETURN (after the full HTTP cycle) also find no `Authorization` header on the `URLConnection` object. Connection-level spin-races that tolerate initially-null `requests` and wait for the `MessageHeader` to materialize still find nothing. That is a result for the tested hooks, not a general egress-control guarantee; a targeted mod may hook a different or earlier path.

### What about FabricLoader? Doesn't it expose the session?

Not in a useful way. `FabricLoader -> GameProvider -> Minecraft -> User` still ends at the same poisoned `User` object, so that path returns the same fake values.

### What if a mod uses Unsafe or VarHandle instead of normal method calls?

Still fake. `Unsafe`, `VarHandle`, `MethodHandle`, and `LambdaMetaFactory` all resolve to the same poisoned fields, so they read the fake values too.

### What about environment variables or process args?

TokenProtector can warn about launcher/OS leaks, but it cannot block them. If your launcher exposes tokens through process args or environment variables, that is outside what a Fabric mod can fully control.

### Can a mod read System.getenv() directly and get my token?

Yes, if your launcher leaked it there first. TokenProtector cannot intercept native JDK environment access, but it can warn you that the leak exists.

### Does it protect launcher files, command lines, or other credentials outside Minecraft?

No. A Fabric mod cannot reliably protect launcher command-line arguments, environment variables, launcher-side token storage, disk credential files, another process, native code, or kernel-level access. Use a trusted launcher and keep the operating system and account secure; TokenProtector only hardens selected in-game JVM paths.

### My friend says "you can't really hide the session token." Are they right?

Normal covered in-game getter, reflection, field, and authlib probes receive fakes. A hostile mod in the same JVM is not contained: it may target TokenProtector, cancel or outrank mixins, run earlier, use an agent, or use an uncovered credential source.

### Will I still be able to join servers?

Yes. Multiplayer, skins, and Realms still work because TokenProtector feeds the real token back only into the narrow auth paths that actually need it.

## Security model

TokenProtector operates entirely within the JVM. It cannot protect against:

- Malware reading the `--accessToken` argument from the OS process list
- Malware reading `launcher_accounts.json` from disk
- A malicious launcher that logs arguments before launching

### Remaining limitations

It is a client-side hardening layer for common in-process token-read paths, not a sandbox or a complete defence against malicious client code. The full research details, including the deeper authlib/JDK probing results, are documented in [WRITEUP.md](WRITEUP.md). For complete session security, combine TokenProtector with a trusted launcher and OS-level hardening.
