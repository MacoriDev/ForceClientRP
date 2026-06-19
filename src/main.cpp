#include <elf.h>
#include <link.h>
#include <pthread.h>
#include <sys/mman.h>
#include <unistd.h>

#include <atomic>
#include <cstdint>
#include <cstring>
#include <vector>

namespace {

constexpr const char* kTargetModule = "libminecraftpe.so";
constexpr uint32_t kStrbUnsignedMask = 0xFFC00000u;
constexpr uint32_t kStrbUnsignedValue = 0x39000000u;
constexpr uint32_t kRegisterMask = 0x1Fu;

struct BytePattern {
    const int* bytes = nullptr;
    size_t size = 0;
};

struct PatchSpec {
    BytePattern pattern;
    size_t patchOffset = 0;
    uint32_t expectedImmediate = 0;
};

struct PatchGroup {
    const PatchSpec* patches = nullptr;
    size_t count = 0;
};

struct ExecSegment {
    uintptr_t start = 0;
    size_t size = 0;
};

struct ModuleInfo {
    uintptr_t base = 0;
    std::vector<ExecSegment> execSegments;
};

std::atomic<bool> g_workerStarted{false};

// Legacy layout used by 26.23. These patterns intentionally include a few
// wildcards around branch immediates/register bytes, but still require both
// ResourcePacksInfoPacket and ResourcePackStackPacket anchors to match exactly
// once before anything is patched.
constexpr int kInfoRequiredFlagPatternLegacy[] = {
    0xE8, 0x03, 0x6C, 0x39,
    -1,   -1,   -1,   0x34,
    0xE8, 0x03, 0x6B, 0x39,
    -1,   0xC3, 0x00, 0x39,
    0xA8, 0xE3, 0x03, 0xD1,
    0xE0, 0x03, 0x14, 0xAA,
};
constexpr int kStackRequiredFlagPatternLegacy[] = {
    0xE8, 0x43, 0x49, 0x39,
    0xF7, 0x03, 0x15, 0xAA,
    -1,   0xA2, 0x01, 0x39,
    0xA8, 0xE9, 0x02, 0xD0,
    0x08, 0x81, 0x3D, 0x91,
    0xA9, 0x03, 0x04, 0xD1,
};

// Modern layout used by 26.30 and 26.31. This avoids hard Build-ID matching so
// minor updates with the same packet-read layout keep working. No private
// MinecraftPackets::createPacket signature is present or scanned here.
constexpr int kInfoRequiredFlagPatternModern[] = {
    0xA8, 0x03, 0x54, 0x38,
    0xE8, 0xC3, 0x29, 0x39,
    -1,   -1,   -1,   0x34,
    0xA8, 0x03, 0x50, 0x38,
    0xE8, 0xC3, 0x28, 0x39,
    -1,   0xC3, 0x00, 0x39,
    0xA8, 0x03, 0x04, 0xD1,
    0xE0, 0x03, 0x14, 0xAA,
};
constexpr int kStackRequiredFlagPatternModern[] = {
    0xE8, 0x43, 0x57, 0x39,
    -1,   -1,   -1,   0x34,
    0xE8, 0xC3, 0x59, 0x39,
    -1,   -1,   -1,   0x34,
    0xE8, 0xC3, 0x58, 0x39,
    -1,   0xA2, 0x01, 0x39,
    0xA8, 0x83, 0x01, 0xD1,
    0xE0, 0x03, 0x15, 0xAA,
};

constexpr PatchSpec kLegacyPatches[] = {
    {{kInfoRequiredFlagPatternLegacy, sizeof(kInfoRequiredFlagPatternLegacy) / sizeof(kInfoRequiredFlagPatternLegacy[0])}, 12, 0x30},
    {{kStackRequiredFlagPatternLegacy, sizeof(kStackRequiredFlagPatternLegacy) / sizeof(kStackRequiredFlagPatternLegacy[0])}, 8, 0x68},
};

constexpr PatchSpec kModernPatches[] = {
    {{kInfoRequiredFlagPatternModern, sizeof(kInfoRequiredFlagPatternModern) / sizeof(kInfoRequiredFlagPatternModern[0])}, 20, 0x30},
    {{kStackRequiredFlagPatternModern, sizeof(kStackRequiredFlagPatternModern) / sizeof(kStackRequiredFlagPatternModern[0])}, 20, 0x68},
};

constexpr PatchGroup kPatchGroups[] = {
    {kLegacyPatches, sizeof(kLegacyPatches) / sizeof(kLegacyPatches[0])},
    {kModernPatches, sizeof(kModernPatches) / sizeof(kModernPatches[0])},
};

bool contains(const char* haystack, const char* needle) {
    return haystack && needle && std::strstr(haystack, needle) != nullptr;
}

uint32_t readU32(const void* address) {
    uint32_t value = 0;
    std::memcpy(&value, address, sizeof(value));
    return value;
}

void writeU32(void* address, uint32_t value) {
    std::memcpy(address, &value, sizeof(value));
}

bool patternMatches(const uint8_t* ptr, const int* pattern, size_t patternSize) {
    for (size_t i = 0; i < patternSize; ++i) {
        if (pattern[i] >= 0 && ptr[i] != static_cast<uint8_t>(pattern[i])) {
            return false;
        }
    }
    return true;
}

std::vector<uintptr_t> scanSegment(const ExecSegment& seg, const int* pattern, size_t patternSize) {
    std::vector<uintptr_t> matches;
    if (seg.start == 0 || seg.size < patternSize) return matches;

    const auto* begin = reinterpret_cast<const uint8_t*>(seg.start);
    const size_t limit = seg.size - patternSize;
    for (size_t i = 0; i <= limit; ++i) {
        if (patternMatches(begin + i, pattern, patternSize)) {
            matches.push_back(seg.start + i);
            if (matches.size() > 1) break;
        }
    }
    return matches;
}

std::vector<uintptr_t> scanAllExecutableSegments(const ModuleInfo& module, const int* pattern, size_t patternSize) {
    std::vector<uintptr_t> matches;
    for (const ExecSegment& seg : module.execSegments) {
        std::vector<uintptr_t> local = scanSegment(seg, pattern, patternSize);
        matches.insert(matches.end(), local.begin(), local.end());
        if (matches.size() > 1) break;
    }
    return matches;
}

int phdrCallback(dl_phdr_info* info, size_t, void* data) {
    auto* out = static_cast<ModuleInfo*>(data);
    if (!info || !contains(info->dlpi_name, kTargetModule)) {
        return 0;
    }

    out->base = static_cast<uintptr_t>(info->dlpi_addr);
    for (int i = 0; i < info->dlpi_phnum; ++i) {
        const ElfW(Phdr)& phdr = info->dlpi_phdr[i];
        if (phdr.p_type == PT_LOAD && (phdr.p_flags & PF_X) != 0) {
            ExecSegment seg;
            seg.start = out->base + static_cast<uintptr_t>(phdr.p_vaddr);
            seg.size = static_cast<size_t>(phdr.p_memsz);
            out->execSegments.push_back(seg);
        }
    }
    return 1;
}

bool findTargetModule(ModuleInfo& info) {
    info = ModuleInfo{};
    dl_iterate_phdr(phdrCallback, &info);
    return info.base != 0 && !info.execSegments.empty();
}

bool setPageProtection(void* address, size_t length, int prot) {
    const long pageSize = sysconf(_SC_PAGESIZE);
    if (pageSize <= 0) return false;

    const uintptr_t mask = static_cast<uintptr_t>(pageSize) - 1;
    const uintptr_t start = reinterpret_cast<uintptr_t>(address) & ~mask;
    const uintptr_t end = (reinterpret_cast<uintptr_t>(address) + length + mask) & ~mask;
    return ::mprotect(reinterpret_cast<void*>(start), end - start, prot) == 0;
}

void flushInstructionCache(void* address, size_t length) {
    __builtin___clear_cache(reinterpret_cast<char*>(address), reinterpret_cast<char*>(address) + length);
}

uint32_t getUnsignedImmediateByteOffset(uint32_t instruction) {
    return (instruction >> 10u) & 0xFFFu;
}

bool isExpectedStrbStore(uint32_t instruction, uint32_t expectedImmediate) {
    if ((instruction & kStrbUnsignedMask) != kStrbUnsignedValue) return false;
    const uint32_t immediate = getUnsignedImmediateByteOffset(instruction);
    if (immediate != expectedImmediate) return false;
    const uint32_t sourceRegister = instruction & kRegisterMask;
    return sourceRegister == 8u || sourceRegister == 31u;
}

uint32_t forceStoreSourceRegisterToWzr(uint32_t instruction) {
    return (instruction & ~kRegisterMask) | 31u;
}

bool findSingleValidatedPatchAddress(const ModuleInfo& module, const PatchSpec& spec, uintptr_t& outPatchAddr) {
    std::vector<uintptr_t> matches = scanAllExecutableSegments(module, spec.pattern.bytes, spec.pattern.size);
    if (matches.size() != 1) return false;

    const uintptr_t patchAddr = matches[0] + spec.patchOffset;
    const uint32_t current = readU32(reinterpret_cast<const void*>(patchAddr));
    if (!isExpectedStrbStore(current, spec.expectedImmediate)) return false;

    outPatchAddr = patchAddr;
    return true;
}

bool groupIsApplicable(const ModuleInfo& module, const PatchGroup& group) {
    if (group.patches == nullptr || group.count == 0) return false;
    for (size_t i = 0; i < group.count; ++i) {
        uintptr_t unused = 0;
        if (!findSingleValidatedPatchAddress(module, group.patches[i], unused)) {
            return false;
        }
    }
    return true;
}

bool patchSingleInstruction(uintptr_t patchAddr, uint32_t expectedImmediate) {
    auto* address = reinterpret_cast<void*>(patchAddr);
    const uint32_t current = readU32(address);
    if (!isExpectedStrbStore(current, expectedImmediate)) return false;

    const uint32_t patchedInstruction = forceStoreSourceRegisterToWzr(current);
    if (current == patchedInstruction) return true;

    if (!setPageProtection(address, sizeof(uint32_t), PROT_READ | PROT_WRITE | PROT_EXEC)) {
        return false;
    }

    writeU32(address, patchedInstruction);
    flushInstructionCache(address, sizeof(uint32_t));

    setPageProtection(address, sizeof(uint32_t), PROT_READ | PROT_EXEC);
    return readU32(address) == patchedInstruction;
}

void applyGroup(const ModuleInfo& module, const PatchGroup& group) {
    for (size_t i = 0; i < group.count; ++i) {
        uintptr_t patchAddr = 0;
        if (findSingleValidatedPatchAddress(module, group.patches[i], patchAddr)) {
            patchSingleInstruction(patchAddr, group.patches[i].expectedImmediate);
        }
    }
}

void applyPatches(const ModuleInfo& module) {
    size_t applicableGroupCount = 0;
    size_t applicableGroupIndex = 0;
    for (size_t i = 0; i < sizeof(kPatchGroups) / sizeof(kPatchGroups[0]); ++i) {
        if (groupIsApplicable(module, kPatchGroups[i])) {
            ++applicableGroupCount;
            applicableGroupIndex = i;
        }
    }

    // Patch only when exactly one complete InfoPacket + StackPacket layout is
    // recognized. This prevents accidental cross-version false positives.
    if (applicableGroupCount == 1) {
        applyGroup(module, kPatchGroups[applicableGroupIndex]);
    }
}

void* workerThread(void*) {
    for (int attempt = 0; attempt < 300; ++attempt) {
        ModuleInfo module;
        if (findTargetModule(module)) {
            applyPatches(module);
            return nullptr;
        }
        usleep(100000);
    }
    return nullptr;
}

void startWorkerOnce() {
    bool expected = false;
    if (!g_workerStarted.compare_exchange_strong(expected, true)) {
        return;
    }

    pthread_t thread{};
    if (pthread_create(&thread, nullptr, workerThread, nullptr) == 0) {
        pthread_detach(thread);
    }
}

} // namespace

extern "C" __attribute__((visibility("default"))) void mod_preinit() {
    startWorkerOnce();
}

extern "C" __attribute__((visibility("default"))) void mod_init() {
    startWorkerOnce();
}

__attribute__((constructor)) static void constructorEntry() {
    startWorkerOnce();
}
