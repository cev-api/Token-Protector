# TokenProtector
![TokenProtector icon](src/main/resources/TP.png)

### Real-time session token protection for Minecraft 26.1.2 Fabric

## What it does

TokenProtector prevents malicious mods from stealing your Minecraft session token. It sits between the game's authentication system and every mod in your instance, serving fake token data to unauthorized callers while keeping multiplayer, skins, and Realms fully functional.

## How it works
![Graphic](https://i.imgur.com/G0UHemM.png)

**The real token never touches any object a mod can read.** It's saved in an internal stash and fed directly to authlib's HTTP client. In the authlib object, it's fake at rest and only swapped to real during the ~1 ms window of an actual HTTP request to Mojang's servers. Every User getter checks the caller's stack trace - Minecraft internals (`net.minecraft.*`, `com.mojang.*`) get real values, mods get fakes.

For more information on how and why this program was written check out the [write up](https://github.com/cev-api/Token-Protector/blob/main/WRITEUP.md).

## Attack surface coverage

| Attack vector | Status | Returns |
|---|---|---|
| `User.getAccessToken()` | ❌ Blocked | Configurable fake |
| `Field.get("accessToken")` | ❌ Blocked | Field itself is poisoned |
| `Unsafe.getObject(offset)` | ❌ Blocked | Field is fake at rest |
| `MethodHandle` / `LambdaMetaFactory` | ❌ Blocked | Same field, same poison |
| Authlib `MinecraftClient.accessToken` (Unsafe) | ❌ Blocked | Time-window swap to fake |
| Knot ClassLoader bypass | ❌ Blocked | Same call chain → same fake |
| Legacy Yarn/MCP probes | ❌ Blocked | 26.1.2 is unmapped |
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

1. Download `tokenprotector-1.0.0.jar` from [Releases](../../releases)
2. Place in `mods/` folder
3. Requires **Minecraft 26.1.2**, **Fabric Loader 0.19.2+**, **Fabric API**, **Java 25**
4. Mod Menu is optional but recommended for the settings screen

## Testing

A comprehensive token-reader mod was used to verify the protection. Every probe technique returned fake data:

```
getAccessToken()        → FAKE_TOKEN      ← getter is blocked
accessToken (field)     → FAKE_TOKEN      ← field is poisoned at construction
MinecraftClient.accessToken → FAKE_TOKEN  ← authlib field time-window blocked
Unsafe.getObject()      → FAKE_TOKEN      ← field-level read is blocked
MethodHandle / Lambda   → FAKE_TOKEN      ← all reflection paths blocked
Legacy class_320/Session → CLASS NOT FOUND ← 26.1.2 unmapped, dead paths
```

While still being able to join multiplayer servers - the real token reaches Mojang's authlib through a separate channel that mod code cannot reach.


## Building from source

```powershell
$env:JAVA_HOME = 'C:\Program Files\Eclipse Adoptium\jdk-25.0.2.10-hotspot'
./gradlew build --no-daemon
```

Requires JDK 25 and Gradle 9.1.0+. Output at `build/libs/tokenprotector-1.0.0.jar`.


## FAQ

### Can't a mod just mix into authlib to get the token?

No. The `User` object's `accessToken` **field itself** is overwritten with a fake value at construction - before any mod can read it. Mixing into authlib just means you arrive at the same poisoned field. The real token only lives in `TokenStash` (a package-private holder outside any game class) and `MinecraftClient.accessToken` (which is also faked at rest by `AuthlibMixin`).

### What about FabricLoader? Doesn't it expose the session?

FabricLoader provides `FabricLoader.getInstance().getGameProvider()`, and the game provider holds a reference to `Minecraft`. But `Minecraft.getUser()` returns the **same User object** whose fields are already poisoned. The chain `FabricLoader → GameProvider → Minecraft → User → accessToken` hits the same fake field. There's no separate token copy.

### What if a mod uses Unsafe or VarHandle instead of normal method calls?

Still returns fake data. `Unsafe.getObject(user, accessTokenOffset)` reads the field's object reference from memory - and that reference points to the fake string because `UserMixin` replaces it at construction. VarHandle, MethodHandle, and LambdaMetaFactory all resolve to the same field read.

### What about environment variables or process args?

TokenProtector scans `System.getenv()`, `System.getProperties()`, and `ProcessHandle.commandLine()` at startup and warns you if your launcher is leaking tokens at the OS level. However, **it cannot block native API calls** - if your launcher puts tokens in environment variables, any process on your PC can read them. This is a launcher issue, not something a Minecraft mod can fix.

### Can a mod read System.getenv() directly and get my token?

Yes - and TokenProtector can't intercept native JDK methods. But it **will** scan at startup and alert you that the leak exists, so you can switch to a launcher that doesn't expose tokens this way.

### My friend says "you can't really hide the session token." Are they right?

They're confusing "hide completely" with "block every practical attack." Can someone with a kernel debugger, a custom JVM agent, or physical machine access read your token? Yes. Can a mod in your `mods/` folder? **No** - every JVM-level read path returns fake data. The legitimate Minecraft code that needs the real token (authlib's HTTP client) receives it through a side channel that mod code cannot reach.

### Will I still be able to join servers?

Yes. The real token reaches Mojang's authlib through `MinecraftMixin.restoreRealTokenForAuthlib()` which restores it only for the `createUserApiService` call. Multiplayer, skins, and Realms all work normally.

## Security model

TokenProtector operates entirely within the JVM. It cannot protect against:

- Malware reading the `--accessToken` argument from the OS process list
- Malware reading `launcher_accounts.json` from disk
- A malicious launcher that logs arguments before launching

### The authlib time-window

`MinecraftClient.accessToken` stores a fake value at rest and is swapped to the real token only during the ~1 ms of an actual HTTP call to Mojang's servers.  A mod with `sun.misc.Unsafe` access, the exact field offset discovered, and a tight spin-loop polling at microsecond intervals could theoretically catch the real value during that window.

In practice this requires:

- `Unsafe.getUnsafe()` or reflective access to `theUnsafe` (restricted on Java 25)
- Manual field-offset discovery on `MinecraftClient` inside a foreign JAR
- Polling at 10,000+ reads/second - extremely noisy and detectable
- Perfect timing luck (the window opens unpredictably on a background IO thread)

No known stealer mod uses this technique - they all call `getUser().getAccessToken()` or `Field.get("accessToken")`, both of which return `FAKE_TOKEN`.  If you encounter a mod that does CPU-spiking Unsafe spin-loops on authlib internals, it will trigger a `🔴 SPIN-RACE DETECTED` alert and it will appear in the Recent Detections tab.

### What a mod cannot do

A mod **cannot** make its own authenticated Mojang API call.  The real token is never exposed to mod code - it's fed directly from `TokenStash` to authlib's `createUrlConnection()` internally.  A mod has no way to call Mojang's API itself unless it already has the token, which TokenProtector prevents.

For complete session security, combine TokenProtector with a trusted launcher and OS-level hardening.
