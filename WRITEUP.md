# Minecraft Token Protection Writeup

## Overview

This document explains how the my Token Protector Fabric mod was developed, what it achieved, and why the real security boundary is not just the JVM. It also describes the different types of token reads, why there are so many attack vectors, why obfuscation is easy for stealers, and why OS-level attacks cannot be blocked by a Fabric mod.

---

## Development story

### 1. Start with the flow

The project began by mapping the Minecraft 26.1.2 authentication pipeline:

- PrismLauncher passes `--accessToken` to the game process.
- Minecraft constructs a `net.minecraft.client.User` instance.
- Minecraft initializes authlib through `Minecraft.createUserApiService()`.
- `com.mojang.authlib.minecraft.client.MinecraftClient` holds the token for Mojang HTTP calls.
- The game calls Mojang APIs for login, multiplayer, skins, and Realms.

That flow reveals two key facts:

1. The real token must reach authlib.
2. Every mod in `mods/` can inspect game objects and reflection paths.

### 2. Build a validation harness first

A separate token-reader app was built as a read-only probe suite. It does not mutate game state. Instead, it tests every suspected path and writes the result to a text file.

This harness makes the protection measurable. It answers the core question:

- "Can a mod read the real token even if another mod actively tries to block it?"

### 2.5. Build the stealer before the protector

The token-reader itself was written as a Fabric mod that behaves like a malicious stealer.
It uses 90+ distinct probe methods across 11 categories, including both obvious attacks and exotic, esoteric, obfuscated reads.
That approach ensures the protection is not just "good enough for simple mods" but robust against real attacker behavior.

**Due to the malicious nature of the mod, it won't be released to the public.** It is simply far too easy to convert into actual malware and may be used as a learning tool to obfuscate token reading.

### 3. Add multiple defensive layers

The Token Protector’s design is intentionally layered:

- Stash the real token away from mod-visible objects.
- Poison every `User` field and getter that a mod can see.
- Keep authlib’s internal token fake at rest.
- Only restore the real token for the exact instant an HTTP request is sent.
- Detect rapid polling and suspicious side-channel probes.

### 4. Validate iteratively

After every defensive change, the token reader is run again. This is why the reader had so many different methodologies and was exhaustive.

The result is a protection model where every mod-visible path returns fake data, while Mojang API access still works.

---

## What it achieved

![Graphic](https://i.imgur.com/G0UHemM.png)

### Complete JVM-side protection against normal mods

My Token Protector shows that a Fabric mod can successfully block these token reads:

- `User.getAccessToken()` and all normal public accessors.
- Java reflection on `User` field values.
- `Unsafe.getObject(...)` reads on the same fields.
- `VarHandle` and `MethodHandle` access paths.
- Legacy session class names from old Minecraft versions.
- Obfuscated name lookups designed to evade simple string matching.

### Real auth still works

The real token is still delivered to Mojang authlib through a separate channel.

That means:

- Multiplayer login succeeds.
- Skins and capes still load.
- Realms access still works.

### The protector identifies advanced attacks

The system also tracks suspicious behavior:

- rapid authlib token polling,
- repeated unsafe field reads,
- legacy/unmapped token probes,
- launcher/OS token exposure.

This is critical because the remaining risk is not a normal getter but a timing/side-channel attack.

### The spin-race exception

The one probe that still challenges the system is the concurrent spin-race.
This probe polls `MinecraftClient.accessToken` at maximum speed during server connection and auth handshake, trying to catch the tiny moment when authlib restores the real token for an HTTP request.

Token Protector does not fail quietly here; it detects the behavior and logs it as suspicious.
That means the protection is still effective in practice, because the only remaining risk is an active, noisy timing attack that is detectable.

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

The token reader also hooks key lifecycle moments:

- when the client starts connecting to a server,
- when the handshake begins,
- when `MinecraftClient` is constructed.

These are the moments a stealer is most likely to read a token.

### 9. Concurrent time-window attack

The final probe is a spin-race.

It polls `MinecraftClient.accessToken` at extreme speed during server join. If the protector only swaps tokens slowly, the real JWT can be caught in the small window when authlib temporarily restores it for an HTTP request.

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

### What my Token Protector mod can do

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

The development of my Token Protector proves that a Fabric mod can harden Minecraft 26.1.2 against common token-stealing techniques by:

- isolating the real token from mod-visible objects,
- poisoning all exposed values,
- detecting side-channel polling,
- and validating the result with a broad probe suite.

It is important to understand the gap it closes:

- 90+ methods were tested, including public APIs, reflection, legacy names, obfuscation, unsafe memory access, authlib internals, and constructor-time reads.
- The only remaining test that can still see the token is a spin-race timing attack during the authlib HTTP window.
- That spin race is not a silent failure mode; it is noisy and detectable, which is significantly better than allowing silent token theft.

So yes - this is sufficient to block the practical mod-level attack surface, and it is far better than nothing.

It also proves that some attacks are simply outside the mod’s control:

- command-line leaks,
- environment variable leaks,
- launcher-side token storage,
- and disk-based credential files.

That is why the final recommendation is:

- use Token Protector to defend the JVM layer,
- use a trusted launcher and OS configuration for the process layer,
- and keep the validation harness as a separate audit tool.
