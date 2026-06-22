# ForceServerGlobalResource V15 Diagnostic

GPL-3.0-only.

Diagnostic build for Minecraft Bedrock Android 26.23/26.30/26.31 ARM64.

This version intentionally includes logcat output so failed minor-version updates can be diagnosed.
It does not include or scan the private MinecraftPackets::createPacket signature.

Logcat:

```bash
adb logcat -c
adb logcat -v time -s ForceServerGlobalResource
```

Current status:

- Resource pack JSON files are not modified when joining a server, so V15 ignores `global_resource_packs.json` and persistence paths.
- V11/V12 confirmed that packet boolean patches are applied on 26.31.
- V13 stack counters did not fix 26.31, so those are removed.
- V14 server-required UI/session flag did not fix 26.31, so that patch is removed.

V15 focus:

- Keeps only the known packet boolean patches.
- Adds diagnostics for in-memory active pack labels: `activeTexturePacks`, `globalTexturePacks`, `activeBehaviorPacks`, `resourcePackStack`, and `ResourcePackStack`.
- Logs each string xref and nearest detected function start so the next build can target the actual active stack replacement function instead of file/packet/UI paths.

Expected diagnostic lines:

```text
V15 diagnostic: ignoring global_resource_packs.json
active-stack diagnostic string activeTexturePacks rva=...
active-stack diagnostic xref activeTexturePacks count=...
active-stack diagnostic xref activeTexturePacks adrp=... functionStart=...
```

This is a diagnostic build, not a no-log public release.
