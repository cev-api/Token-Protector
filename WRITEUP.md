# Token Protection Writeup

## Overview

TokenProtector is a Fabric client mod that reduces Minecraft access-token exposure to other mods.

The mod replaces exposed token values across common Minecraft, Fabric Loader, and authlib paths. It also reports suspicious access and competing instrumentation when it can identify them.

The design protects the data itself. It does not rely only on method names, field names, or known malware signatures.

Normal Minecraft authentication continues to work because TokenProtector keeps the real access token only for the narrow authentication path that needs it.

TokenProtector is designed as practical hardening against malicious or compromised mods. It does not claim to create full process isolation between hostile code that shares the same JVM.

## Security goal and threat model

TokenProtector assumes that another Fabric mod can use normal and advanced same-JVM techniques, including:

- public Minecraft APIs,
- direct field access,
- reflection,
- `Unsafe`,
- `VarHandle`,
- `MethodHandle`,
- `LambdaMetaFactory`,
- generated accessors,
- encoded or obfuscated names,
- Fabric Loader APIs,
- Mixin injection,
- maximum Mixin priority,
- classloader access,
- authlib internals,
- authlib HTTP hooks,
- concurrent polling,
- Fabric `preLaunch` entrypoints,
- dynamic Java-agent self-attach,
- bytecode instrumentation.

TokenProtector also treats launcher, operating-system, native, and filesystem credential copies as a separate trust boundary.

The security goal is:

1. Keep common game-visible and authlib token state on replacement values.
2. Remove the real token from Fabric's retained in-JVM launch arguments before normal game startup.
3. Give the real token only to the authentication path that requires it.
4. Report blocked or suspicious activity when attribution is possible.
5. State the remaining same-JVM and external limits clearly.

## Protection architecture

### Pre-launch argument protection

TokenProtector registers a Fabric `preLaunch` entrypoint.

Fabric keeps parsed launch arguments in the Minecraft game provider. After Fabric finishes the `preLaunch` entrypoints, the provider builds the argument array for `Main.main(String[])` from this retained `Arguments` object with `arguments.toArray()`.

TokenProtector uses its pre-launch handler to:

- capture the real `--accessToken` for the protected authentication path,
- create and register the replacement token,
- replace the retained `accessToken`,
- replace equals-form copies,
- replace matching copies in extra arguments and wrapper payloads,
- preserve the argument shape.

This produces an important result:

```text
launcher credential
      |
      v
Fabric retained Arguments
      |
      | TokenProtector preLaunch capture + scrub
      v
replacement value
      |
      +--> FabricLoader.getLaunchArguments(false)
      |
      +--> Main.main(String[])
      |
      +--> normal Minecraft startup
```

The real token does not need to appear in the later `Main.main` argument array.

This design also protects against the tested dynamic-agent attack at `Main.main` entry. The adversarial TokenReader agent installs during `preLaunch` and registers bytecode advice for `Main.main`. The transformer is active when `Main` loads, but Fabric creates `Main.main`'s array from the retained arguments only after all `preLaunch` entrypoints finish. TokenProtector therefore has an opportunity to scrub the retained data before the agent can observe the method argument.

On the tested run, the first bytecode of `Main.main` receives:

```text
accessToken = FAKE_TOKEN_LOL
```

This result is structural for this specific `Main.main`-entry attack. It does not depend on TokenProtector winning Mixin priority against TokenReader.

Code that directly copies the retained arguments before TokenProtector's own `preLaunch` handler runs remains outside this boundary.

### `Main.main` fallback

TokenProtector also protects `Main.main(...)` at HEAD.

This is a fallback for an environment where the pre-launch path does not run as expected or the delivered argument array still contains an unregistered real token.

If the array already contains a TokenProtector-issued replacement, the fallback does not replace the stored real authentication credential with the fake value.

### Fabric Loader retained arguments

Fabric Loader exposes launch arguments through:

```java
FabricLoader.getInstance().getLaunchArguments(boolean sanitize)
```

TokenProtector protects the retained data itself.

On the tested path:

```text
FabricLoader.getLaunchArguments(false)
    accessToken = FAKE_TOKEN_LOL

FabricLoader.getLaunchArguments(true)
    accessToken option omitted
```

### `User` constructor protection

`UserMixin` rewrites the access-token constructor parameter with `@ModifyVariable`.

The rewrite uses injector order 900.

Ordinary callback injectors use order 1000. This lets TokenProtector replace the token before an ordinary callback at the constructor HEAD receives it.

The adversarial TokenReader also places its constructor Mixin at the Mixin priority ceiling, `Integer.MAX_VALUE`.

The tested constructor still receives:

```text
User.<init> HEAD accessToken = FAKE_TOKEN_LOL
Is JWT (real token)? No
```

This matters because a higher Mixin priority does not automatically defeat the constructor rewrite. Injector order and the final woven bytecode determine the observed value.

An attacker can still try a different injector order or a different transformation mechanism.

The same protection applies when runtime account switching creates another `User`.

### Stored `User` values

Protected `User` state contains replacement values.

Depending on configuration, TokenProtector can replace:

- access token,
- session ID,
- profile UUID,
- XUID,
- client ID,
- player name.

The access-token field itself contains the replacement.

This means a reader that uses reflection, `Unsafe`, `VarHandle`, `MethodHandle`, an encoded field name, or a generated accessor still reads the value stored in that field. Changing the access technique does not reconstruct the original credential.

### Getter protection and caller attribution

TokenProtector intercepts protected caller-aware getters such as:

- `User.getAccessToken()`,
- `User.getSessionId()`,
- `User.getProfileId()`,
- `User.getXuid()`,
- `User.getClientId()`,
- `User.getName()`.

When possible, TokenProtector identifies the caller with stack information, mod ownership, and Mixin metadata.

A blocked event can include:

- mod ID,
- class,
- method,
- source line,
- protected field.

Caller attribution is best effort.

A direct field read or low-level memory read can avoid a getter hook. TokenProtector therefore treats replacement of the underlying data and attribution of a read as separate protections.

### Internal authentication helper

TokenProtector keeps the real token in an internal helper because Minecraft still needs a valid credential for authentication.

The helper does not act as an unrestricted public token getter.

Sensitive reads and mutations check the effective calling context. The gate unwraps common reflection and method-handle frames and can use Mixin metadata to distinguish TokenProtector handlers from foreign merged handlers.

Covered foreign calls are denied.

Examples include:

- direct foreign `forAuthentication()` calls,
- reflective foreign calls,
- method-handle foreign calls,
- foreign attempts to replace the stored credential,
- foreign attempts to add replacement values,
- covered foreign Mixin handlers.

This gate blocks a simple direct API route to the retained token.

The token is also not stored as a plaintext `String`. It is kept masked against a per-capture random pad inside a single opaque record field, so a `getDeclaredField("accessToken")`-style read finds no such field and a blind scan for JWT-shaped static String fields finds nothing. The plaintext is materialised only inside the gated read method itself, immediately before it is handed to an authentication call.

The gate is deliberately not funnelled through one helper method. `forAuthentication()` performs its own inline call-context check, so a hostile agent that retransforms a single shared gate method (for example the former `authorized()` helper) cannot silently open the read path; it would have to rewrite `forAuthentication()` itself.

It is not a memory-isolation boundary. A Java agent that retransforms TokenProtector's own methods can still rewrite `forAuthentication()`, neutralise `platformMethodAuthorized(...)`, or decode the masked pair - an agent is allowed to rewrite the defending code, and no Fabric mod can prevent that. Without an agent, a hostile mod can still attempt `Unsafe`, reflection against the (masked) backing state, bytecode transformation through another loader tier, or execution inside a trusted-looking platform context, but it no longer finds a plaintext token field or a single gate method to neutralise.

### Authlib protection

TokenProtector keeps `com.mojang.authlib.minecraft.client.MinecraftClient.accessToken` on a replacement value at rest on the covered paths.

Version-specific hooks supply the real credential only where the supported authlib flow needs it.

The adversarial TokenReader tests authlib through:

- `get`,
- `getWithEtag`,
- `post`,
- `postWithEtag`,
- `prepareRequest`,
- `postInternal` where present,
- `createUrlConnection`,
- returned `HttpURLConnection` objects,
- internal request-header storage,
- reflection and `Unsafe` through `Minecraft.userApiService`.

The tested authlib object state stays on `FAKE_TOKEN_LOL`.

The tested returned connection objects do not expose an `Authorization` value through the TokenReader probes.

This is not a general network sandbox. Native interception, another HTTP stack, TLS instrumentation, or a different final authentication hook can still operate outside these tested Java paths.

## Detection and posture checks

### Mixin posture

TokenProtector uses high-priority security Mixins on its protected targets.

The configured security priority is `100000`.

TokenProtector inspects protected classes for foreign merged Mixin handlers.

A foreign merge at or above TokenProtector's security priority produces an alert. Lower-priority merges can be reported as informational data.

This detects some attempts to compete with TokenProtector. It does not turn Mixin priority into an enforcement boundary.

A separate Mixin configuration does not provide a general mechanism that can simply delete every other mod's Mixin. A hostile mod can still use different injection points, different injector orders, cancellable handlers where applicable, another transformer, or a Java agent.

### Java-agent and instrumentation posture

TokenProtector checks for signs of more privileged in-JVM instrumentation during its `preLaunch` phase and again on the first client tick.

The checks include:

- mods that declare Fabric `preLaunch` entrypoints,
- known agent tooling on the classpath, such as Byte Buddy agent resources,
- dynamic-attach artifacts,
- protected classes that are loaded but no longer contain TokenProtector's expected merged handlers.

These checks are detection, not enforcement.

They do not prove that token theft occurs.

They also cannot detect every form of instrumentation. An attacker can use unknown tooling, native code, preserve TokenProtector's handlers during retransformation, or begin from outside Fabric.

### External exposure scanner

TokenProtector inspects some environment variables, Java system properties, and process metadata for possible credential exposure.

It understands known credential option names and JWT-shaped or long opaque values in unexpected locations.

A normal authenticated launch includes an `--accessToken` option. TokenProtector treats one normal access-token argument as expected launch exposure rather than proof of malware.

Warnings are reserved for unexpected conditions such as:

- duplicate token copies,
- `--msaToken`,
- refresh-token options,
- unknown JWT-shaped arguments,
- wrapper payloads that contain JWT-shaped values,
- environment-variable credential exposure,
- Java system-property credential exposure.

If Java cannot expose a requested process source, TokenProtector reports the scan as incomplete.

TokenProtector cannot rewrite:

- the native operating-system command line,
- launcher account files,
- launcher logs,
- another process,
- external credential storage.

### Log history and file logging

Every line TokenProtector writes to the console is also kept in two places:

- The Mod Menu "Recent Detections" tab renders the complete in-game history for the current session. The history stores every level (INFO, WARN, ERROR, ALERT), keeps every entry for the session (no 200-entry ring), and renders each line without truncation by wrapping long messages. Only ALERT entries increment the unread counter on the top-right banner; INFO and WARN lines still appear in the history.
- `tokenprotector.log` in the game directory is a separate on-disk archive that appends across sessions. Each session starts with a header line that records the start time and the Minecraft and Fabric Loader versions. File-write failures are swallowed and never affect the game.

## Adversarial verification with TokenReader

### Test profile

TokenReader is a separate adversarial test mod that is intentionally designed to get around TokenProtector.

It contains more than 100 discrete probe paths across 13 categories.

| Category | Attack surface |
|---|---|
| A. Direct API access | Public `User` getters |
| B. Direct field access | Raw `User` fields |
| C. Legacy class names | Old session and Yarn/MCP names |
| D. Legacy fields | Old field names and mappings |
| E. Singleton paths | Minecraft singleton and session-object routes |
| F. Obfuscated access | XOR, Base64, Caesar, split strings, arrays, `MethodHandle`, `LambdaMetaFactory`, `Unsafe`, `VarHandle`, indirect stack calls |
| G. Class-sweep discovery | Static-field search, known names, brute-force names, module search |
| H. Authlib internal chain | `Minecraft.userApiService` to `MinecraftClient.accessToken` through reflection, `Unsafe`, `privateLookupIn`, and object traversal |
| I. Lifecycle and deep HTTP hooks | Construction, connection, handshake, authlib request methods, returned connections |
| J. Concurrent races | High-speed field and connection-header polling |
| K. Auth-service side channels | Authentication-service object discovery and recursive field inspection |
| L. OS and launcher probing | Process metadata, Java properties, environment, Fabric Loader arguments, parent process tree |
| M. Java agent | Self-attached Byte Buddy instrumentation at `Main.main` bytecode entry and authlib connection return points |

The lifecycle and authlib Mixins use `Integer.MAX_VALUE`, the Mixin priority ceiling.

The Java agent self-attaches during Fabric `preLaunch` and instruments the final woven bytecode. Its `Main.main` advice executes before Mixin HEAD handlers.

This test profile is intentionally stronger than a normal token-stealing mod. It attacks the implementation directly rather than only using ordinary Minecraft APIs.

### Runtime result summary

The adversarial run reports replacement data across the tested in-JVM token surfaces.

| Probe | Result |
|---|---|
| Raw Byte Buddy advice at first bytecode of `Main.main` | `FAKE_TOKEN_LOL` |
| TokenReader `Main.main` Mixin at `Integer.MAX_VALUE` | `FAKE_TOKEN_LOL` |
| `User.<init>` HEAD at `Integer.MAX_VALUE` | `FAKE_TOKEN_LOL` |
| `User.getAccessToken()` | `FAKE_TOKEN_LOL` |
| `User.accessToken` | `FAKE_TOKEN_LOL` |
| Encoded and indirect getter paths | `FAKE_TOKEN_LOL` |
| `Unsafe` read of protected `User.accessToken` | `FAKE_TOKEN_LOL` |
| Knot classloader to `Minecraft.getUser().getAccessToken()` | `FAKE_TOKEN_LOL` |
| Authlib `MinecraftClient.accessToken` via `Unsafe` | `FAKE_TOKEN_LOL` |
| Authlib `MinecraftClient.accessToken` via reflection | `FAKE_TOKEN_LOL` |
| Authlib `MinecraftClient.accessToken` via `privateLookupIn` | `FAKE_TOKEN_LOL` |
| Tested authlib method hooks | `FAKE_TOKEN_LOL` |
| `FabricLoader.getLaunchArguments(false)` | `FAKE_TOKEN_LOL` |
| `FabricLoader.getLaunchArguments(true)` | Token option omitted |
| Byte Buddy authlib `HttpURLConnection` return probes | No `Authorization` value observed |
| Runtime account-switch `User` construction | `FAKE_TOKEN_LOL` |
| Reflective read of vault field `accessToken` | Field does not exist (credential masked at rest) |
| Blind scan of static String fields for a JWT | No real token found |
| Agent retransformation of a shared gate helper | No shared `authorized()` helper exists; the read gate is inline in the accessor |
| Reflective `forAuthentication()` after gate-kill attempt | `null` (still denied) |

No Minecraft access token is observed by these covered in-JVM TokenReader probes.

### Dynamic Java-agent test

TokenReader installs Byte Buddy before `Main.main` runs.

Its transformer inserts advice at the first bytecode of `Main.main`. This places TokenReader earlier than every Mixin HEAD handler in that method.

The observed argument is still:

```text
accessToken = FAKE_TOKEN_LOL
```

The same run places TokenReader's normal Mixin at `Integer.MAX_VALUE`. It also sees the replacement.

The reason is the pre-launch retained-argument scrub. Fabric creates `Main.main`'s argument array from the retained `Arguments` after the `preLaunch` phase. TokenProtector replaces the credential in that retained source before the array exists.

This means the tested Java-agent attack cannot recover the launcher token merely by moving to the top of `Main.main`.

This result does not mean all Java agents are harmless. A launcher-supplied `-javaagent`, an earlier `preLaunch` callback that directly reads the retained arguments, or an agent that targets TokenProtector's internal state uses a different attack boundary.

### Mixin-priority and constructor test

TokenReader sets its relevant Mixins and config priority to `2147483647`.

This is the maximum Java `int` value.

The tested `Main.main` and `User` constructor probes still receive the replacement value.

For `Main.main`, the real token is already absent from the delivered argument array.

For the `User` constructor, TokenProtector's `@ModifyVariable` rewrite uses injector order 900, so a simple maximum-priority callback at HEAD does not recover the original token in the tested woven bytecode.

### Obfuscation and indirect-access tests

TokenReader tries to hide what it accesses with:

- XOR-encoded names,
- Base64-encoded names,
- Caesar-shifted names,
- split and reassembled names,
- integer arrays,
- indirect array dispatch,
- anonymous and stack-indirect callers,
- `MethodHandle`,
- `LambdaMetaFactory`,
- reflection,
- `Unsafe`,
- `VarHandle`.

These techniques do not reconstruct a token that is no longer stored in the protected field.

The tested paths continue to receive the replacement or fail access.

### Authlib internal-chain tests

TokenReader traverses:

```text
Minecraft
  -> userApiService
  -> YggdrasilUserApiService
  -> MinecraftClient
  -> accessToken
```

It uses `Unsafe`, reflection, `MethodHandles.privateLookupIn`, and field enumeration.

The protected authlib token remains:

```text
FAKE_TOKEN_LOL
```

### HTTP and final-call tests

TokenReader hooks the tested authlib request path at multiple levels.

It inspects:

- authlib method entry,
- `prepareRequest`,
- `postInternal` where present,
- `createUrlConnection`,
- returned `HttpURLConnection` objects,
- `getRequestProperty("Authorization")`,
- internal `MessageHeader` request storage through `Unsafe`,
- post-call returned connections,
- Byte Buddy advice on authlib methods that return `HttpURLConnection`.

The tested run does not expose an `Authorization` value through these observation points.

Authentication-related Mojang endpoints still return valid data, which shows that normal authenticated functionality continues to work while the exposed authlib state stays replaced.

### Concurrent race tests

TokenReader uses high-speed polling to look for a short interval where the real credential becomes visible.

A 15-second token-field race records:

```text
Total reads: 543484520
Duration: 15000 ms
Baseline: FAKE_TOKEN_LOL
Final value: FAKE_TOKEN_LOL
Value changed: no
```

A separate agent-enabled connection-header race records:

```text
Total reads: 48771570
Duration: 10005 ms
Baseline Authorization: null
Final Authorization: null
requests materialized during spin: false
```

These results show no observable real token in the tested race windows.

### Fabric Loader tests

TokenReader also checks Fabric's own retained argument copies.

The tested unsanitized API returns the replacement:

```text
FabricLoader.getLaunchArguments(false)
    accessToken = FAKE_TOKEN_LOL
```

The tested sanitized API omits the token option.

### OS and launcher probes

TokenReader also checks sources that a Fabric mod cannot fully control:

- `ProcessHandle.info().commandLine()`,
- `ProcessHandle.info().arguments()`,
- `RuntimeMXBean`,
- Java system properties,
- environment variables,
- `sun.java.command`,
- internal process APIs,
- parent and launcher process metadata.

These tests are useful for finding external copies, but they are not equivalent to a bypass of TokenProtector's in-JVM replacement paths.

In the supplied run, Java does not expose the relevant native command line through `ProcessHandle`, so that source remains unverified by the test.

## Security limits

TokenProtector provides strong practical protection on its covered and tested in-JVM paths.

It does not isolate arbitrary hostile code at the process level.

The real token must still exist inside the Minecraft JVM so the client can authenticate.

A determined attacker can still try to operate at a different privilege or timing boundary, including:

- a launcher-supplied `-javaagent`,
- a modified JVM,
- a modified Fabric Loader,
- a `preLaunch` entrypoint that executes before TokenProtector and directly copies the retained arguments,
- instrumentation that retransforms TokenProtector's own methods (for example `forAuthentication()` itself) or decodes the masked retained state,
- direct `Unsafe` or reflective access to TokenProtector's masked backing state,
- bytecode that executes from a context that TokenProtector treats as trusted,
- native code,
- network interception outside the tested Java path,
- launcher-side credential storage,
- operating-system process data,
- filesystem credentials.

The stored credential is masked at rest and the read gate is duplicated, so a name-based field read finds no plaintext token and disabling a single shared gate helper no longer opens the read path. An adaptive reflective or `Unsafe` attacker can still decode the masked pair (masking defeats blind scans, not a determined reader of the class), while retransforming the gated method itself requires Java-agent privilege and remains outside the threat model of ordinary hostile mods.

TokenProtector can detect some of these conditions, but detection does not equal isolation.

A stronger architecture can keep the real credential outside the Minecraft JVM entirely, for example by using a launcher-side authentication broker. TokenProtector does not require a custom launcher and does not provide that architecture.

## Optional JVM hardening

The dynamic self-attach route used by Byte Buddy can also be disabled at JVM startup with:

```text
-XX:+DisableAttachMechanism
```

This option disables the JVM Attach mechanism. TokenProtector cannot enable it after Java starts.

It does not stop a launcher-supplied `-javaagent`, native instrumentation, or a modified JVM or loader.

## FAQ

### Can another Fabric mod simply read the access token?

On the covered paths, ordinary getters, direct protected fields, Fabric Loader's retained argument view, and the tested authlib state return replacement data.

TokenReader verifies these paths with direct, reflective, obfuscated, low-level, and instrumented probes.

### Does a higher Mixin priority defeat TokenProtector?

Not by itself.

TokenReader uses `Integer.MAX_VALUE`, the priority ceiling.

Its tested `Main.main` and constructor handlers still receive `FAKE_TOKEN_LOL`.

For `Main.main`, TokenProtector removes the real token from Fabric's retained argument source before the final array exists.

For the constructor, injector order and final woven bytecode matter in addition to Mixin priority.

### Can another Mixin configuration cancel TokenProtector's Mixins?

Mixin configurations for one target are merged into the same class transformation. There is no general "remove every other mod's Mixin" switch in another config.

A hostile mod can still interfere with particular injection points, use different injector orders, use cancellable handlers where possible, or leave the Mixin system and use another transformer or Java agent.

### Can a dynamic Java agent see the real token at `Main.main` entry?

Not on the tested covered path.

The adversarial TokenReader agent self-attaches during `preLaunch` and inserts advice at the first bytecode of `Main.main`.

That advice receives `FAKE_TOKEN_LOL`.

Fabric creates the `Main.main` argument array from its retained arguments after the `preLaunch` phase, and TokenProtector scrubs that retained source first.

A different agent that runs from the launcher, directly reads retained arguments before TokenProtector, or targets TokenProtector's internal secret state uses a different attack boundary.

### Can TokenReader instrument the authlib HTTP path?

Yes.

It hooks the tested authlib request methods and returned connection objects with both Mixin and Byte Buddy instrumentation.

Those probes receive replacement token state or no observable `Authorization` value in the tested run.

This is evidence for the tested Java path, not a claim of general network isolation.

### What if a mod uses `Unsafe`, reflection, `VarHandle`, or `MethodHandle`?

When these techniques target protected game or authlib fields, they read the replacement that is stored in those fields.

They do not reconstruct the original credential.

Against TokenProtector's own retained state, the credential is masked at rest: there is no plaintext static `String` field to read, and the read gate is duplicated so disabling a single shared helper method does not open it. An adaptive attacker must now decode the masked pair (possible with reflection or `Unsafe`, but requiring them to understand the storage rather than read a named field), while removing the gate by retransformation still requires Java-agent privilege. That remains the documented same-JVM boundary.

### Can a hostile mod read the vault field or disable the gate directly?

A reflective `getDeclaredField("accessToken")` read and a single-method gate retransformation are both removed:

- The token is stored masked against a per-capture random pad in a single opaque record field. A name-based field read finds no `accessToken` field, and a blind scan for JWT-shaped static String fields finds no plaintext.
- The former `authorized()` gate helper no longer exists. `forAuthentication()` performs its own inline call-context check, so an agent that retransforms a shared helper to return `true` has no target that opens the read path.

An attacker who retransforms `forAuthentication()` itself, or who instruments the value at the moment it is decoded for an authentication call, is operating with Java-agent privilege; no Fabric mod can prevent code that is allowed to rewrite the defending code. Decoding the masked pair with reflection or `Unsafe` needs no agent but does require the attacker to adapt to the storage layout instead of reading a named plaintext field. The practical user-side countermeasure for the retransformation route is to start the JVM with `-XX:+DisableAttachMechanism` so dynamic self-attach is unavailable.

### Does Fabric Loader expose the real token?

The tested `FabricLoader.getLaunchArguments(false)` path returns the replacement.

The tested `true` view omits the token option.

Code that directly reads and stores Fabric's retained argument data before TokenProtector's `preLaunch` handler remains outside this protection.

### What about launcher and operating-system process arguments?

TokenProtector cannot rewrite the native operating-system command line or data stored by the launcher.

It can inspect some sources and warn about possible exposure.

These external copies are outside the in-JVM replacement boundary.

### Does a normal `--accessToken` mean the launcher is malicious?

No.

A normal authenticated Minecraft launch supplies this argument.

TokenProtector treats one standard launch token as expected exposure and warns about unexpected copies or unusual credential locations instead.

### Can TokenProtector make the token impossible to steal?

No.

A Fabric mod cannot create a hard isolation boundary against arbitrary hostile code with equal or greater JVM or process privileges.

TokenProtector instead removes the token from the practical surfaces that ordinary and advanced malicious mods commonly target, makes many targeted attacks return replacement data, and reports suspicious activity when it can identify it.

### Does multiplayer still work?

Yes.

The tested client completes normal authenticated Minecraft operations while the covered public fields, getters, Fabric Loader arguments, authlib state, agent probes, and concurrent race probes continue to show replacement data or no observable auth header.

### Does obfuscation defeat TokenProtector?

Not by itself.

Obfuscation can hide how an attacker locates a field or method. It does not change the replacement value stored in the protected field.

## Assessment

TokenProtector is a practical same-JVM hardening layer for Fabric clients.

Its strongest property is that it replaces the data at multiple storage and handoff points instead of only trying to detect known stealer code.

The adversarial TokenReader test is explicitly designed to defeat it. TokenReader uses more than 100 probe paths across direct APIs, raw fields, obfuscation, class discovery, authlib internals, high-priority Mixins, concurrent races, Fabric Loader state, deep HTTP hooks, OS and launcher probing, and a self-attached Byte Buddy Java agent.

On the tested in-JVM paths, these probes receive replacement data or no observable authentication header.

The Byte Buddy agent is a particularly strong test. It installs during Fabric `preLaunch`, instruments the final woven `Main.main` bytecode, and executes before every Mixin HEAD handler in that method. It still receives `FAKE_TOKEN_LOL` because TokenProtector removes the real token from Fabric's retained argument source before Fabric constructs the `Main.main` array.

TokenReader also uses `Integer.MAX_VALUE` Mixins, direct and reflective field access, `Unsafe`, `privateLookupIn`, authlib object traversal, deep connection hooks, and high-speed races. The tested protected surfaces remain on replacement data while authentication continues to work.

This does not make the JVM a sandbox. A more privileged attacker can still run before TokenProtector's pre-launch boundary, target TokenProtector's private retained state, use native code, or obtain an external token copy.

Within its stated scope, TokenProtector makes token theft substantially harder and forces an attacker away from common and moderately advanced Fabric-stealer techniques toward narrower, more targeted, and more privileged attack paths.
