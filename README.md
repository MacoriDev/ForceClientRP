# ForceServerGlobalResource V13 Diagnostic

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

- V11/V12 confirmed that ResourcePacksInfoPacket and ResourcePackStackPacket boolean stores are patched on 26.31.
- 26.30 worked with the packet-flag approach, but 26.31 still removes global resource packs after those booleans are forced false.
- Comparing 26.30 and 26.31 showed the packet read functions are almost identical and shifted, so V13 now also patches ResourcePackStackPacket 32-bit server-stack counters.

V13 additions:

- Keeps the InfoPacket boolean patches.
- Keeps the StackPacket boolean patches.
- Stops patching the StackPacket return/status object field at `x19 + 0x40` because it is not a packet field.
- Adds StackPacket word-counter patches at `x20 + 0x50`, `x20 + 0x64`, and `x20 + 0x6c`.
- Keeps static xref diagnostics for global-pack/resource-pack strings.

Expected new log lines:

```text
patched modern stack word counters STR x20#0x50 ...
patched modern stack word counters STR x20#0x64 ...
patched modern stack word counters STR x20#0x6c ...
```

This is not a no-log public release build yet.
