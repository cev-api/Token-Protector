# TokenProtector
![TokenProtector icon](src/main/resources/TP.png)

### Real-time session token protection for Minecraft 1.21.x / 26.1.x Fabric

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
| `User.getSessionId()` | ❌ Blocked | Configurable fake |
| `Field.get("accessToken")` | ❌ Blocked | Field itself is poisoned |
| `Unsafe.getObject(offset)` | ❌ Blocked | Field is fake at rest |
| `MethodHandle` / `LambdaMetaFactory` | ❌ Blocked | Same field, same poison |
| Authlib `MinecraftClient.accessToken` (Unsafe) | ❌ Blocked | Time-window swap to fake |
| Knot ClassLoader bypass | ❌ Blocked | Same call chain → same fake |
| Hook `MinecraftClient.postInternal` / `setRequestProperty("Authorization", "Bearer " + token)` | ❌ Blocked | Field is fake at rest |
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
3. Requires **Minecraft 1.21.x** (Java 21) or **26.1.x** (Java 25), **Fabric Loader 0.16.10+**, **Fabric API**
4. Mod Menu is optional but recommended for the settings screen

## Testing

A comprehensive token-reader mod was used to verify the protection. Every probe technique - including the `postInternal` → `setRequestProperty("Authorization", "Bearer " + token)` deep-hook attack suggested by the Ratter Scanner community - returned fake data:

```
getAccessToken()        → FAKE_TOKEN      ← getter is blocked
getSessionId()          → FAKE_TOKEN      ← getter is blocked
accessToken (field)     → FAKE_TOKEN      ← field is poisoned at construction
MinecraftClient.accessToken → FAKE_TOKEN  ← authlib field time-window blocked
Unsafe.getObject()      → FAKE_TOKEN      ← field-level read is blocked
MethodHandle / Lambda   → FAKE_TOKEN      ← all reflection paths blocked
Legacy class_320/Session → CLASS NOT FOUND ← 26.1.2 unmapped, dead paths
postInternal Bearer header → FAKE_TOKEN_LOL ← authlib HTTP layer is blocked
get/post/createUrlConnection  → FAKE_TOKEN_LOL ← all authlib entry points blocked
```

While still being able to join multiplayer servers - the real token reaches Mojang's authlib through a separate channel that mod code cannot reach.


## Building from source

### Build both versions at once (recommended)

```powershell
$env:JAVA_HOME = 'C:\Program Files\Eclipse Adoptium\jdk-25.0.2.10-hotspot'
./gradlew build --no-daemon
```

Produces:
- `build/libs/tokenprotector-1.0.0-mc1.21.11.jar`
- `build/libs/tokenprotector-1.0.0-mc26.1.2.jar`

No editing of `gradle.properties` needed. `build` delegates to the internal multi-version build and compiles both jars in sequence.

### Build a single version

Edit `gradle.properties` and set the version you want, then `./gradlew build`. Even easier: use `-P` flags without editing any files:

```powershell
# For 1.21.x:
./gradlew build --no-daemon -Ptokenprotector_single_build=true -Ploom_plugin_id=fabric-loom -Ploom_version=1.15.5 -Pminecraft_version=1.21.11 -Pmappings_mode=official -Pfabric_version=0.141.4+1.21.11 -Ploader_version=0.18.4 -Pmodmenu_version=11.0.3 -Pjava_version=21

# For 26.1.x:
./gradlew build --no-daemon -Ptokenprotector_single_build=true -Ploom_plugin_id=net.fabricmc.fabric-loom -Ploom_version=1.16.3 -Pminecraft_version=26.1.2 -Pfabric_version=0.149.1+26.1.2 -Ploader_version=0.19.2 -Pmodmenu_version=18.0.0-beta.1 -Pjava_version=25
```

The 1.21 source set is compatible with **all** 1.21.x versions (the `User` API is stable across the entire 1.21 line). The `fabric.mod.json` uses a version range (`>=1.21.1 <1.22` or `>=26.1.0 <27`) so the JAR loads on any matching Minecraft version.


## FAQ

### Can't a mod just mix into authlib to get the token?

No. The `User` object's `accessToken` **field itself** is overwritten with a fake value at construction - before any mod can read it. Mixing into authlib just means you arrive at the same poisoned field. The real token only lives in `TokenStash` (a package-private holder outside any game class) and `MinecraftClient.accessToken` (which is also faked at rest by `AuthlibMixin`).

### What about hooking the HTTP request itself? Can a mod intercept `postInternal` and grab the token from `connection.setRequestProperty("Authorization", "Bearer " + token)`?

This was the specific attack vector raised by a reviewer in the Ratter Scanner Discord: if TokenProtector only protects `User`/`Session`-level access, what stops an attacker from hooking deeper - into authlib's `postInternal` method where the `Authorization: Bearer <token>` header is set on the `HttpURLConnection`?

This was tested with a dedicated deep-hook probe. The result: **blocked.** TokenProtector poisons `MinecraftClient.accessToken` at the field level, so when `postInternal` reads `this.accessToken` to build the `Bearer` header, it gets `FAKE_TOKEN_LOL` - just like every other read path. The fake token propagates all the way to the HTTP request.

**How it was tested:** The TokenReader test harness was updated with `@Inject` hooks on all authlib HTTP entry points (`postInternal`, `post`, `get`, `createUrlConnection`). Every intercept showed `FAKE_TOKEN_LOL` during live server joins. The exact attack the reviewer described was reproduced and blocked.

**Why not hook `HttpURLConnection.setRequestProperty` directly?** A real stealer can't `@Mixin` JDK classes - they're loaded during JVM bootstrap before Mixin initializes. Attempting it crashes with `MixinTargetAlreadyLoadedException`. The practical stealer approach is to hook `MinecraftClient.postInternal` (which is what the deep-hook probe does), and that path is already covered.

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

Note: The real token only appears during the swap window inside the `MinecraftClient.accessToken` field. The deep HTTP hooks on `postInternal` and `post`/`get` confirmed that by the time authlib actually makes its HTTP requests and sets the `Authorization: Bearer` header, the field has already been re-poisoned. The Bearer header sent to Mojang's servers contains `FAKE_TOKEN_LOL` - not the real token. 

In practice this requires:

- `Unsafe.getUnsafe()` or reflective access to `theUnsafe` (restricted on Java 25)
- Manual field-offset discovery on `MinecraftClient` inside a foreign JAR
- Polling at 10,000+ reads/second - extremely noisy and detectable
- Perfect timing luck (the window opens unpredictably on a background IO thread)

No known stealer mod uses this technique - they all call `getUser().getAccessToken()` or `Field.get("accessToken")`, both of which return `FAKE_TOKEN`.  If you encounter a mod that does CPU-spiking Unsafe spin-loops on authlib internals, it will trigger a `🔴 SPIN-RACE DETECTED` alert and it will appear in the Recent Detections tab.

### What a mod cannot do

A mod **cannot** make its own authenticated Mojang API call.  The real token is never exposed to mod code - it's fed directly from `TokenStash` to authlib's `createUrlConnection()` internally.  A mod has no way to call Mojang's API itself unless it already has the token, which TokenProtector prevents.

For complete session security, combine TokenProtector with a trusted launcher and OS-level hardening.
