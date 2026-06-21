#include <android/log.h>
#include <elf.h>
#include <link.h>
#include <pthread.h>
#include <sys/mman.h>
#include <unistd.h>

#include <atomic>
#include <cstdint>
#include <cstring>
#include <cstdio>
#include <vector>

namespace {

constexpr const char* kTag = "ForceServerGlobalResource";
constexpr const char* kTargetModule = "libminecraftpe.so";
constexpr uint32_t kStrbUnsignedMask = 0xFFC00000u;
constexpr uint32_t kStrbUnsignedValue = 0x39000000u;
constexpr uint32_t kStrUnsignedMask = 0xFFC00000u;
constexpr uint32_t kStrUnsignedValue = 0xB9000000u;
constexpr uint32_t kRegisterMask = 0x1Fu;

#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, kTag, __VA_ARGS__)
#define LOGW(...) __android_log_print(ANDROID_LOG_WARN, kTag, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, kTag, __VA_ARGS__)

struct BytePattern { const int* bytes = nullptr; size_t size = 0; const char* name = nullptr; };
struct PatchSpec { BytePattern pattern; size_t patchOffset = 0; uint32_t expectedImmediate = 0; const char* name = nullptr; };
struct ExecSegment { uintptr_t start = 0; size_t size = 0; };
struct ModuleInfo { uintptr_t base = 0; std::vector<ExecSegment> execSegments; };

std::atomic<bool> g_workerStarted{false};

constexpr int kInfoRequiredFlagPatternLegacy[] = {
    0xE8, 0x03, 0x6C, 0x39, -1, -1, -1, 0x34,
    0xE8, 0x03, 0x6B, 0x39, -1, 0xC3, 0x00, 0x39,
    0xA8, 0xE3, 0x03, 0xD1, 0xE0, 0x03, 0x14, 0xAA,
};
constexpr int kStackRequiredFlagPatternLegacy[] = {
    0xE8, 0x43, 0x49, 0x39, 0xF7, 0x03, 0x15, 0xAA,
    -1, 0xA2, 0x01, 0x39, 0xA8, 0xE9, 0x02, 0xD0,
    0x08, 0x81, 0x3D, 0x91, 0xA9, 0x03, 0x04, 0xD1,
};

constexpr int kInfoRequiredFlagPatternModern[] = {
    0xA8, 0x03, 0x54, 0x38, 0xE8, 0xC3, 0x29, 0x39,
    -1, -1, -1, 0x34, 0xA8, 0x03, 0x50, 0x38,
    0xE8, 0xC3, 0x28, 0x39, -1, 0xC3, 0x00, 0x39,
    0xA8, 0x03, 0x04, 0xD1, 0xE0, 0x03, 0x14, 0xAA,
};
constexpr int kStackRequiredFlagPatternModern[] = {
    0xE8, 0x43, 0x57, 0x39, -1, -1, -1, 0x34,
    0xE8, 0xC3, 0x59, 0x39, -1, -1, -1, 0x34,
    0xE8, 0xC3, 0x58, 0x39, -1, 0xA2, 0x01, 0x39,
    0xA8, 0x83, 0x01, 0xD1, 0xE0, 0x03, 0x15, 0xAA,
};

constexpr PatchSpec kLegacyExactPatches[] = {
    {{kInfoRequiredFlagPatternLegacy, sizeof(kInfoRequiredFlagPatternLegacy) / sizeof(kInfoRequiredFlagPatternLegacy[0]), "legacy-info"}, 12, 0x30, "legacy info #0x30"},
    {{kStackRequiredFlagPatternLegacy, sizeof(kStackRequiredFlagPatternLegacy) / sizeof(kStackRequiredFlagPatternLegacy[0]), "legacy-stack"}, 8, 0x68, "legacy stack #0x68"},
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
        if (pattern[i] >= 0 && ptr[i] != static_cast<uint8_t>(pattern[i])) return false;
    }
    return true;
}

std::vector<uintptr_t> scanSegment(const ExecSegment& seg, const int* pattern, size_t patternSize, size_t maxMatches = 4) {
    std::vector<uintptr_t> matches;
    if (!seg.start || seg.size < patternSize) return matches;
    const auto* begin = reinterpret_cast<const uint8_t*>(seg.start);
    const size_t limit = seg.size - patternSize;
    for (size_t i = 0; i <= limit; ++i) {
        if (patternMatches(begin + i, pattern, patternSize)) {
            matches.push_back(seg.start + i);
            if (matches.size() >= maxMatches) break;
        }
    }
    return matches;
}

std::vector<uintptr_t> scanAllExecutableSegments(const ModuleInfo& module, const int* pattern, size_t patternSize, size_t maxMatches = 4) {
    std::vector<uintptr_t> matches;
    for (const ExecSegment& seg : module.execSegments) {
        std::vector<uintptr_t> local = scanSegment(seg, pattern, patternSize, maxMatches - matches.size());
        matches.insert(matches.end(), local.begin(), local.end());
        if (matches.size() >= maxMatches) break;
    }
    return matches;
}

int phdrCallback(dl_phdr_info* info, size_t, void* data) {
    auto* out = static_cast<ModuleInfo*>(data);
    if (!info || !contains(info->dlpi_name, kTargetModule)) return 0;
    out->base = static_cast<uintptr_t>(info->dlpi_addr);
    for (int i = 0; i < info->dlpi_phnum; ++i) {
        const ElfW(Phdr)& phdr = info->dlpi_phdr[i];
        if (phdr.p_type == PT_LOAD && (phdr.p_flags & PF_X) != 0) {
            out->execSegments.push_back({out->base + static_cast<uintptr_t>(phdr.p_vaddr), static_cast<size_t>(phdr.p_memsz)});
        }
    }
    return 1;
}

bool findTargetModule(ModuleInfo& info) {
    info = ModuleInfo{};
    dl_iterate_phdr(phdrCallback, &info);
    return info.base != 0 && !info.execSegments.empty();
}

bool addressInExecutableSegment(const ModuleInfo& module, uintptr_t address) {
    for (const ExecSegment& seg : module.execSegments) {
        if (address >= seg.start && address < seg.start + seg.size) return true;
    }
    return false;
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

uint32_t getBaseRegister(uint32_t instruction) {
    return (instruction >> 5u) & 0x1Fu;
}

uint32_t getRtRegister(uint32_t instruction) {
    return instruction & 0x1Fu;
}

bool isStrbUnsignedStore(uint32_t instruction) {
    return (instruction & kStrbUnsignedMask) == kStrbUnsignedValue;
}

bool isStrUnsignedStore(uint32_t instruction) {
    return (instruction & kStrUnsignedMask) == kStrUnsignedValue;
}

bool isExpectedStrbStore(uint32_t instruction, uint32_t expectedImmediate) {
    return isStrbUnsignedStore(instruction) && getUnsignedImmediateByteOffset(instruction) == expectedImmediate;
}

uint32_t forceStoreSourceRegisterToWzr(uint32_t instruction) {
    return (instruction & ~kRegisterMask) | 31u;
}

bool patchSingleInstruction(const ModuleInfo& module, uintptr_t patchAddr, uint32_t expectedImmediate, const char* label) {
    if (!addressInExecutableSegment(module, patchAddr)) {
        LOGW("skip %s: addr not executable rva=0x%zx", label, static_cast<size_t>(patchAddr - module.base));
        return false;
    }
    auto* address = reinterpret_cast<void*>(patchAddr);
    const uint32_t current = readU32(address);
    if (!isExpectedStrbStore(current, expectedImmediate)) {
        LOGW("skip %s: not expected STRB rva=0x%zx ins=0x%08x imm=0x%x rn=x%u rt=w%u", label,
             static_cast<size_t>(patchAddr - module.base), current, getUnsignedImmediateByteOffset(current), getBaseRegister(current), getRtRegister(current));
        return false;
    }
    const uint32_t patched = forceStoreSourceRegisterToWzr(current);
    if (current == patched) {
        LOGI("already patched %s rva=0x%zx", label, static_cast<size_t>(patchAddr - module.base));
        return true;
    }
    if (!setPageProtection(address, sizeof(uint32_t), PROT_READ | PROT_WRITE | PROT_EXEC)) {
        LOGE("mprotect RWX failed %s rva=0x%zx", label, static_cast<size_t>(patchAddr - module.base));
        return false;
    }
    writeU32(address, patched);
    flushInstructionCache(address, sizeof(uint32_t));
    setPageProtection(address, sizeof(uint32_t), PROT_READ | PROT_EXEC);
    const bool ok = readU32(address) == patched;
    LOGI("%s %s rva=0x%zx old=0x%08x new=0x%08x imm=0x%x rn=x%u", ok ? "patched" : "patch failed", label,
         static_cast<size_t>(patchAddr - module.base), current, patched, expectedImmediate, getBaseRegister(current));
    return ok;
}

bool findSingleValidatedPatchAddress(const ModuleInfo& module, const PatchSpec& spec, uintptr_t& outPatchAddr) {
    std::vector<uintptr_t> matches = scanAllExecutableSegments(module, spec.pattern.bytes, spec.pattern.size, 4);
    LOGI("pattern %s match count=%zu", spec.pattern.name, matches.size());
    for (uintptr_t m : matches) LOGI("pattern %s match rva=0x%zx", spec.pattern.name, static_cast<size_t>(m - module.base));
    if (matches.size() != 1) return false;
    const uintptr_t patchAddr = matches[0] + spec.patchOffset;
    const uint32_t current = readU32(reinterpret_cast<const void*>(patchAddr));
    if (!isExpectedStrbStore(current, spec.expectedImmediate)) {
        LOGW("pattern %s target invalid rva=0x%zx ins=0x%08x", spec.pattern.name, static_cast<size_t>(patchAddr - module.base), current);
        return false;
    }
    outPatchAddr = patchAddr;
    return true;
}

size_t applyExactPatchSpecs(const ModuleInfo& module, const PatchSpec* patches, size_t count) {
    size_t patched = 0;
    for (size_t i = 0; i < count; ++i) {
        uintptr_t patchAddr = 0;
        if (findSingleValidatedPatchAddress(module, patches[i], patchAddr)) {
            if (patchSingleInstruction(module, patchAddr, patches[i].expectedImmediate, patches[i].name)) ++patched;
        }
    }
    return patched;
}

bool inList(uint32_t v, const uint32_t* list, size_t count) {
    for (size_t i = 0; i < count; ++i) if (list[i] == v) return true;
    return false;
}

size_t patchStrbStoresNear(const ModuleInfo& module,
                           const char* group,
                           uintptr_t anchor,
                           intptr_t startDelta,
                           size_t length,
                           uint32_t expectedBaseRegister,
                           const uint32_t* targetOffsets,
                           size_t targetOffsetCount) {
    if (!anchor) return 0;
    size_t patched = 0;
    uintptr_t start = static_cast<uintptr_t>(static_cast<intptr_t>(anchor) + startDelta);
    start &= ~static_cast<uintptr_t>(3);
    for (size_t off = 0; off + sizeof(uint32_t) <= length; off += sizeof(uint32_t)) {
        uintptr_t addr = start + off;
        if (!addressInExecutableSegment(module, addr)) continue;
        uint32_t ins = readU32(reinterpret_cast<const void*>(addr));
        if (!isStrbUnsignedStore(ins)) continue;
        if (getBaseRegister(ins) != expectedBaseRegister) continue;
        const uint32_t imm = getUnsignedImmediateByteOffset(ins);
        if (!inList(imm, targetOffsets, targetOffsetCount)) continue;
        char label[96]{};
        snprintf(label, sizeof(label), "%s x%u#0x%x", group, expectedBaseRegister, imm);
        if (patchSingleInstruction(module, addr, imm, label)) ++patched;
    }
    LOGI("group %s patched count=%zu", group, patched);
    return patched;
}

size_t applyModernNeighborhoodPatches(const ModuleInfo& module) {
    size_t patched = 0;
    std::vector<uintptr_t> infoMatches = scanAllExecutableSegments(
        module, kInfoRequiredFlagPatternModern, sizeof(kInfoRequiredFlagPatternModern) / sizeof(kInfoRequiredFlagPatternModern[0]), 4);
    LOGI("pattern modern-info match count=%zu", infoMatches.size());
    for (uintptr_t m : infoMatches) LOGI("pattern modern-info match rva=0x%zx", static_cast<size_t>(m - module.base));
    if (infoMatches.size() == 1) {
        constexpr uint32_t kInfoOffsets[] = {0x30, 0x31, 0x32, 0x33, 0x60};
        patched += patchStrbStoresNear(module, "modern info", infoMatches[0], 0, 0x220, 28, kInfoOffsets, sizeof(kInfoOffsets) / sizeof(kInfoOffsets[0]));
    }

    std::vector<uintptr_t> stackMatches = scanAllExecutableSegments(
        module, kStackRequiredFlagPatternModern, sizeof(kStackRequiredFlagPatternModern) / sizeof(kStackRequiredFlagPatternModern[0]), 4);
    LOGI("pattern modern-stack match count=%zu", stackMatches.size());
    for (uintptr_t m : stackMatches) LOGI("pattern modern-stack match rva=0x%zx", static_cast<size_t>(m - module.base));
    if (stackMatches.size() == 1) {
        constexpr uint32_t kStackOffsets[] = {0x54, 0x68, 0xD8, 0xD9};
        patched += patchStrbStoresNear(module, "modern stack payload", stackMatches[0], -0x420, 0x980, 20, kStackOffsets, sizeof(kStackOffsets) / sizeof(kStackOffsets[0]));

        // 26.30/26.31 contain one adjacent optional-state boolean written as STRB w8, [x19,#0x40]
        // near the same payload read. This diagnostic build patches it too so we can test whether
        // the global-pack removal moved behind this additional packet flag. If this fixes the game,
        // the release build can keep this one; if it breaks server packs, remove it again.
        constexpr uint32_t kOptionalOffsets[] = {0x40};
        patched += patchStrbStoresNear(module, "modern stack optional", stackMatches[0], -0x420, 0x980, 19, kOptionalOffsets, sizeof(kOptionalOffsets) / sizeof(kOptionalOffsets[0]));
    }
    return patched;
}

void applyPatches(const ModuleInfo& module) {
    LOGI("module base=%p execSegments=%zu", reinterpret_cast<void*>(module.base), module.execSegments.size());
    for (const ExecSegment& seg : module.execSegments) {
        LOGI("exec segment rva=0x%zx size=0x%zx", static_cast<size_t>(seg.start - module.base), seg.size);
    }
    size_t patched = 0;
    patched += applyExactPatchSpecs(module, kLegacyExactPatches, sizeof(kLegacyExactPatches) / sizeof(kLegacyExactPatches[0]));
    patched += applyModernNeighborhoodPatches(module);
    LOGI("patch summary totalPatched=%zu", patched);
}

void* workerThread(void*) {
    LOGI("module loaded, worker started, diagnostic build");
    for (int attempt = 0; attempt < 300; ++attempt) {
        ModuleInfo module;
        if (findTargetModule(module)) {
            applyPatches(module);
            return nullptr;
        }
        usleep(100000);
    }
    LOGE("libminecraftpe.so not found after retries");
    return nullptr;
}

void startWorkerOnce() {
    bool expected = false;
    if (!g_workerStarted.compare_exchange_strong(expected, true)) return;
    pthread_t thread{};
    if (pthread_create(&thread, nullptr, workerThread, nullptr) == 0) pthread_detach(thread);
}

} // namespace

extern "C" __attribute__((visibility("default"))) void mod_preinit() { startWorkerOnce(); }
extern "C" __attribute__((visibility("default"))) void mod_init() { startWorkerOnce(); }
__attribute__((constructor)) static void constructorEntry() { startWorkerOnce(); }
