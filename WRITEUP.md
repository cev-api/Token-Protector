# Token Protection Writeup

## Overview

This document explains TokenProtector's hardening of common Minecraft session-token read paths, the different types of token reads, why there are many attack vectors, and why a Fabric mod cannot create a security boundary against hostile code in the same JVM or OS-level attacks.

---

## Defense layers

TokenProtector uses multiple overlapping layers to reduce exposure on its covered paths. No Fabric mod can ensure that a hostile peer mod cannot bypass, cancel, or target those layers.

### 1. Bootstrap interception (MainMixin)

`MainMixin` intercepts the `new User(...)` call in `Main.main()` via `@ModifyArg`. At this covered boundary, the real JWT is captured in an internal authentication helper and a fake token is substituted as the `accessToken` constructor argument. The tested constructor-time probes see a fake. Code that runs earlier or interferes with mixin transformation/order is outside this guarantee.

### 2. Field poisoning (UserMixin)

`UserMixin` fires at `@At("RETURN")` of the `User` constructor. It reads the internal authentication helper as the source of truth and stores non-token session values in `TokenVault`. Then it overwrites every visible `User` field (`accessToken`, `uuid`, `xuid`, `clientId`, `name`) with configurable fake replacements.

All public getters (`getAccessToken()`, `getSessionId()`, etc.) are also intercepted and return fake values to unauthorized callers.

### 3. Authlib protection

`com.mojang.authlib.minecraft.client.MinecraftClient.accessToken` is kept fake at rest. Version-specific hooks cover the supported authlib methods (`get`, `postInternal`, or `prepareRequest` depending on authlib). The regression probes see the fake value; this does not cover every possible network or egress hook.

The real token is reintroduced only through narrow protected call-site redirects at the exact Mojang auth paths that need it (join server, refresh, etc.). It is never restored into the public authlib field for normal request building.

### 4. Spin-race protection

Because `MinecraftClient.accessToken` stays fake at rest, polling that field at high speed with `Unsafe` only returns the fake value. The traditional "read one field 20 million times per second" spin-race does not work - there is no window where the real token briefly appears in that field.

The included connection-level spin-race probe did not observe an `Authorization` header in the inspected `URLConnection.requests` map. That result is specific to the tested path; it does not establish that every header, socket, or third-party network hook is covered.

A targeted mod can still attempt bytecode interception of the redirected auth path, an earlier hook, mixin cancellation/priority changes, a JVM agent, or an alternative credential source.

### 5. Side-channel and polling detection

TokenProtector tracks suspicious behavior patterns:

- rapid authlib token polling,
- repeated unsafe field reads,
- legacy/unmapped token probes,
- launcher/OS token exposure.

---

### Real auth still works

Multiplayer login, skins, capes, and Realms all function because the real token is delivered to Mojang's auth endpoints through the narrow protected redirects - not through the normal public getters or fields that mods can read.

---

## Types of token reads

The token reader tests every meaningful category of access.

### 1. Public API reads

These are the simplest and most common attacks.

- `User.getAccessToken()`
- `User.getSessionId()`
- `User.getProfileId()`
- `User.getXuid()`
- `User.getClientId()`

If these are blocked, the first line of defense is working.

### 2. Direct field access

Modders can bypass getters by reading fields directly.

- `Field.get(user, "accessToken")`
- `Field.get(user, "uuid")`
- `Field.get(user, "xuid")`

This proves protection must poison the underlying field itself, not just the getter.

### 3. Legacy class access

Many stealers are written for old Minecraft versions.

They look for classes like:

- `client.session.Session`
- `client.util.Session`
- `util.Session`
- `class_320`

These are thrown at the JVM because a mod can still load old code paths or use old assumptions. If the protection only covers current names, it is incomplete.

### 4. Legacy field access

Even if the class exists, field names may differ.

Older mods or leaked code may try fields such as:

- `field_1983`
- `field_1982`
- `field_34960`
- `field_148258_c`

The harness checks those too.

### 5. Singleton and client path probes

A mod can try to reach the token through the Minecraft instance:

- `MinecraftClient.getInstance().getUser()`
- `MinecraftClient.getInstance().session`
- `MinecraftClient.getInstance().field_1726`

These paths are especially important because they are often the first thing a malicious mod tries.

### 6. Obfuscated access techniques

Token stealers can hide the real names, so the protector must not rely on string matching.

The probe suite tests:

- XOR-encoded class/method names
- Base64-encoded identifiers
- Caesar-shifted strings
- split/reassembled identifiers
- names built from raw int arrays
- dynamic `MethodHandle` lookups
- `LambdaMetaFactory` generated accessors

Why so many? Because real malware does not use plain strings. It reconstructs identifiers at runtime to evade detection.

### 7. Authlib internal chain

The true hard target is authlib's internal token storage.

That chain includes:

- private fields on `Minecraft` and authlib objects
- the `YggdrasilUserApiService` implementation
- `MinecraftClient.accessToken`

A protection mod must verify that even these internal objects do not leak the real token to mods.

### 8. Constructor-time capture

The token reader hooks key lifecycle moments where a stealer is most likely to read a token:

- when the client starts connecting to a server,
- when the handshake begins,
- when `MinecraftClient` is constructed.

The covered bootstrap boundary substitutes a fake token for `User` construction; the internal helper remains the source for redirected authentication calls. The tested constructor-time probes see a fake, but an earlier observer or mod that interferes with mixin transformation/order is not ruled out. If you whitelist a mod that performs its own `User` construction (e.g. an alt-account manager), that mod is explicitly trusted and may receive real values through the allowed path - TokenProtector cannot prevent a trusted mod from exposing what it has been allowed to access.

### 9. Concurrent time-window attack (spin-race)

This probe polls `MinecraftClient.accessToken` at extreme speed during server join, hoping to catch the real JWT in a brief window where authlib temporarily holds it. This does not succeed against TokenProtector because `MinecraftClient.accessToken` stays fake at rest - the real token is never written into that public field. Polling it at any speed only returns the fake value.

### 9.5. Post-call connection probes

These probes hook authlib's `getWithEtag`/`postWithEtag` at `RETURN` - after the full HTTP cycle completes - and inspect the `URLConnection` object:

- `connection.getRequestProperty("Authorization")` - checks if the header was set during the connect/read phase
- Unsafe access to `URLConnection.requests` (the internal `MessageHeader` map) - may be materialized post-call
- `URLConnection.connected` - confirms the socket was established

These probes inspect the connection object after the HTTP cycle. The tested probe did not observe the real token or an `Authorization` header in that map. This is a result for that inspected path, not a claim that every connection or socket layer is covered.

### 9.6. Connection spin-race (materialization-tolerant)

Unlike the authlib field race, this probe targets the `URLConnection` object directly. It spins on `Unsafe.getObject(connection, requestsOffset)` in a tight loop for up to 10 seconds, waiting for the internal `MessageHeader` map to materialize (pop from null to an actual object) mid-connection. Once materialized, it switches to the fast Unsafe -> `MessageHeader` path and races on header inspection.

This tested spin-race did not observe an `Authorization` header in the inspected map. It does not establish that a different connection implementation, socket hook, or egress path is protected.

### 10. OS-level process probing

These are not protections; they are leak detectors.

They search:

- `ProcessHandle.info().commandLine()`
- `RuntimeMXBean.getInputArguments()`
- system properties containing `token`, `access`, `session`, or `auth`
- environment variables like `TOKEN`, `ACCESS`, `MINECRAFT`, `MOJANG`
- `sun.java.command`

These methods show why the launcher or OS can leak tokens even if the JVM is locked down.

---

## Why there are so many probes

Because there are many distinct ways to reach the same secret.

### Different abstraction levels

A token can be read at any of these levels:

- clean API calls (`User.getAccessToken()`)
- private field reads (`Field.get(...)`)
- unsafe memory access (`Unsafe`, `VarHandle`)
- generated call sites (`MethodHandle`, `LambdaMetaFactory`)
- obfuscated runtime string assembly
- legacy class names and fields
- authlib internals
- operating system process metadata

Each of those is a separate attack surface.

### Different attacker assumptions

A stealer can be:

- a naive mod using public getters,
- a complex mod using reflection,
- a legacy mod using old class names,
- an obfuscated mod trying to evade detection,
- a side-channel attacker timing the authlib window,
- a launcher or OS process reading the token before the JVM starts.

A protection app cannot ignore any of those assumptions.

### Easy to obfuscate means easy to hide from heuristics

Most mod-based token stealers rely on the same underlying read operation: read a String field from a game object.

What changes is only how the code refers to that field.

That is why obfuscation is cheap:

- build the class name at runtime
- decode the method name from bytes
- use `MethodHandle` instead of a direct call
- use `LambdaMetaFactory` to create a function object

The actual secret access still follows the same path.

So the defender must protect the data, not just block specific names.

---

## Why obfuscation is easy for stealers

A stealer does not need to be a full malware product.

For a Fabric mod, the JVM gives you everything:

- runtime reflection
- module access if you can use `MethodHandles.privateLookupIn`
- `Unsafe` when a mod can obtain it by reflection
- the same classloader as the game
- the same process arguments and environment

In this environment, hiding your intent is cheap:

- mod code is still executed by the game,
- strings can be reconstructed at runtime,
- any access path can be wrapped in a generated lambda,
- the JVM does not prevent you from calling `Field.get()` on private data if you already have the object.

So attackers simply move from "name-based detection" to "behavior-based detection." That is why the protection app is designed around data poisoning and token isolation instead of blocking a fixed list of identifiers.

---

## Why OS-level attacks cannot be blocked by a Fabric mod

A Fabric mod runs inside the Minecraft JVM. That gives it power over Java objects, but not over the process launcher or the operating system.

### OS-level leaks are outside the JVM boundary

Examples:

- `--accessToken` on the command line
- `System.getenv("ACCESS_TOKEN")`
- `ProcessHandle.info().commandLine()`
- `launcher_accounts.json` on disk
- any native launcher API that exposes secrets

A Fabric mod cannot alter the OS process listing, the environment, or the launcher's behavior after the game starts.

### What the mod can do

A mod can only:

- detect the leak,
- warn the user,
- avoid exposing the same secret again inside the JVM.

It cannot stop another process from reading the process command line or environment variables.

### Why that matters

If the launcher puts the token in an environment variable or command line argument, every process on the machine may be able to read it.

That is a fundamentally different class of attack than a malicious mod.

A good protection strategy is therefore:

- protect the JVM-visible token paths,
- and still treat launcher/OS leaks as a separate, higher-privilege threat.

---

## Summary

TokenProtector hardens Minecraft against common token-stealing techniques through overlapping defensive layers:

- **Bootstrap interception** - the real JWT is stashed before any other mod's `User` constructor hook fires; the constructor argument itself is poisoned.
- **Field and getter poisoning** - every visible `User` field and getter returns fake values to unauthorized callers.
- **Authlib protection** - `MinecraftClient.accessToken` stays fake at rest; the real token is only reintroduced at the narrow auth endpoints that need it.
- **Spin-race protection** - polling `MinecraftClient.accessToken` or `URLConnection` headers at any speed returns the fake value because the real token never enters those objects. Connection-level materialization-tolerant races also find no `Authorization` header.
- **Side-channel detection** - suspicious polling, repeated unsafe reads, and legacy probes are tracked and surfaced.

Over 90 probe methods across 11 categories have been tested: public APIs, reflection, legacy names, obfuscation, unsafe memory access, authlib internals, constructor-time reads, post-call connection probes, and connection-level spin-races. With protection enabled and the test mod unwhitelisted, the supported probes returned fake data while multiplayer, skins, and Realms continued to work through protected auth redirects.

Some attacks are outside the scope of a Fabric mod:

- command-line leaks,
- environment variable leaks,
- launcher-side token storage,
- and disk-based credential files.

The recommendation is to combine TokenProtector (JVM layer) with a trusted launcher and OS-level hardening for the process and filesystem layers.
