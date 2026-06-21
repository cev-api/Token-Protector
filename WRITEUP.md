# Token Protection Writeup

## Overview

This document explains how TokenProtector defends the Minecraft session token, why the real security boundary is not just the JVM, the different types of token reads, why there are so many attack vectors, why obfuscation is easy for stealers, and why OS-level attacks cannot be blocked by a Fabric mod.

---

## Defense layers

TokenProtector uses multiple overlapping layers so that no single bypass undoes the protection.

### 1. Bootstrap interception (MainMixin)

`MainMixin` intercepts the `new User(...)` call in `Main.main()` via `@ModifyArg`. Before any other mod's constructor mixin fires, the real JWT is stashed into `TokenStash.realAccessToken` and a fake token is substituted as the `accessToken` constructor argument. A malicious `@Inject(method="<init>", at=@At("HEAD"))` on `User` sees only the fake value.

### 2. Field poisoning (UserMixin)

`UserMixin` fires at `@At("RETURN")` of the `User` constructor. It reads `TokenStash.realAccessToken` as the source of truth and stores the real session values in `TokenVault`. Then it overwrites every visible `User` field (`accessToken`, `uuid`, `xuid`, `clientId`, `name`) with configurable fake replacements.

All public getters (`getAccessToken()`, `getSessionId()`, etc.) are also intercepted and return fake values to unauthorized callers.

### 3. Authlib protection

`com.mojang.authlib.minecraft.client.MinecraftClient.accessToken` is kept fake at rest. Deep hooks on authlib methods (`get`, `post`, `postInternal`, `prepareRequest`) see the fake value - normal field reads never expose the real JWT.

The real token is reintroduced only through narrow protected call-site redirects at the exact Mojang auth paths that need it (join server, refresh, etc.). It is never restored into the public authlib field for normal request building.

### 4. Spin-race protection

Because `MinecraftClient.accessToken` stays fake at rest, polling that field at high speed with `Unsafe` only returns the fake value. The traditional "read one field 20 million times per second" spin-race does not work - there is no window where the real token briefly appears in that field.

Connection-level spin-races also fail. A race on `URLConnection.requests` (Unsafe→`MessageHeader`) that waits for the header map to materialize mid-connection still finds no `Authorization` header, because the real token is never written to the connection object's header map. The `Authorization` header is set at a lower JDK socket level that a normal Fabric mod cannot hook easily.

A bypass would require a much harder bytecode-level interception of the exact protected auth redirect path or native socket interception, not a field-read race. Even that is detectable as suspicious behavior.

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

The true hard target is authlib’s internal token storage.

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

Bootstrap-boundary constructor argument capture does not work. A malicious `@Inject(method="<init>", at=@At("HEAD"))` on `User` sees only the fake `accessToken` parameter because `MainMixin` intercepts the `new User(...)` call via `@ModifyArg` and substitutes a fake token before any observer fires. The real JWT is already in `TokenStash.realAccessToken` by then, and `UserMixin` uses that as the source of truth so `TokenVault` still receives the real value for protected auth paths.

### 9. Concurrent time-window attack (spin-race)

This probe polls `MinecraftClient.accessToken` at extreme speed during server join, hoping to catch the real JWT in a brief window where authlib temporarily holds it. This does not succeed against TokenProtector because `MinecraftClient.accessToken` stays fake at rest - the real token is never written into that public field. Polling it at any speed only returns the fake value.

### 9.5. Post-call connection probes

These probes hook authlib's `getWithEtag`/`postWithEtag` at `RETURN` - after the full HTTP cycle completes - and inspect the `URLConnection` object:

- `connection.getRequestProperty("Authorization")` - checks if the header was set during the connect/read phase
- Unsafe access to `URLConnection.requests` (the internal `MessageHeader` map) - may be materialized post-call
- `URLConnection.connected` - confirms the socket was established

These probes test whether the protector injects the real token into the connection object during the connect or read phase, rather than at the `prepareRequest` point (where headers are still null). This does not succeed because the real token is never placed into the connection's header map - the `Authorization` header is set at a lower JDK socket layer.

### 9.6. Connection spin-race (materialization-tolerant)

Unlike the authlib field race, this probe targets the `URLConnection` object directly. It spins on `Unsafe.getObject(connection, requestsOffset)` in a tight loop for up to 10 seconds, waiting for the internal `MessageHeader` map to materialize (pop from null to an actual object) mid-connection. Once materialized, it switches to the fast Unsafe→`MessageHeader` path and races on header inspection.

This does not succeed because the `Authorization` header is never added to the connection's header map. The real token bypasses `URLConnection.getRequestProperty()` / `requests` entirely; it is set at a lower socket-write level.

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

### “Easy to obfuscate” means “easy to hide from heuristics”

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

A Fabric mod cannot alter the OS process listing, the environment, or the launcher’s behavior after the game starts.

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

Over 90 probe methods across 11 categories have been tested: public APIs, reflection, legacy names, obfuscation, unsafe memory access, authlib internals, constructor-time reads, post-call connection probes, and connection-level spin-races. All return fake data to unauthorized callers while multiplayer, skins, and Realms continue to work through protected auth redirects.

Some attacks are outside the scope of a Fabric mod:

- command-line leaks,
- environment variable leaks,
- launcher-side token storage,
- and disk-based credential files.

The recommendation is to combine TokenProtector (JVM layer) with a trusted launcher and OS-level hardening for the process and filesystem layers.
