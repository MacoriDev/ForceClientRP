# ForceServerGlobalResource V14 Diagnostic

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
- V13 counter patching did not fix 26.31, so V14 stops patching StackPacket counters.
- The global resource pack JSON file is not changed by joining a server, so V14 ignores file persistence and targets the in-memory server-required session path instead.

V14 additions:

- Keeps InfoPacket boolean patches.
- Keeps StackPacket boolean patches.
- Removes V13 StackPacket word-counter patches.
- Adds a patch near the `resource_pack_download_server_required` string xref.
- The new patch forces the in-memory server-required session flag load `ldrb w?, [x22, #0x58]` to zero by replacing it with `mov w?, #0`.

Expected new log lines:

```text
server-required string rva=...
server-required xref count=1
patched server-required session flag x22#0x58 -> w9=0 ...
```

This is still a diagnostic build, not a no-log public release.
