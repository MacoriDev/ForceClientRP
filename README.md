# ForceServerGlobalResource V12 Diagnostic

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

- Packet flag patches are applied to ResourcePacksInfoPacket and ResourcePackStackPacket.
- If global resource packs still get removed after `patch summary totalPatched` is non-zero, the remaining issue is probably after packet read: the server pack stack is replacing/filtering the active global resource pack stack.

V12 additions:

- Keeps the V11 packet flag patches.
- Adds static xref diagnostics for global-pack and resource-pack-manager strings such as `global_resource_packs.json`, `world_resource_packs.json`, `ResourcePackManager::_doStackOperation`, and server-required resource-pack UI strings.
- These logs are used to choose the next hook/patch target for the active stack merge/filter stage.

This is not a no-log public release build yet.
