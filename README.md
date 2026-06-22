# ForceServerGlobalResource V11 Diagnostic

GPL-3.0-only.

Diagnostic build for Minecraft Bedrock Android 26.23/26.30/26.31 ARM64.

This version intentionally includes logcat output so failed minor-version updates can be diagnosed.
It does not include or scan the private MinecraftPackets::createPacket signature.

Logcat:

```bash
adb logcat -c
adb logcat -v time -s ForceServerGlobalResource
```

The module patches ResourcePacksInfoPacket and ResourcePackStackPacket boolean stores discovered by public packet-read patterns. It also reports patch counts and RVAs so a no-log release can be made after confirmation.
