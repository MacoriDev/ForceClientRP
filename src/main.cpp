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

// Minecraft Bedrock Android 26.23 ARM64.
// ResourcePacksInfoPacket::_read required/must-accept flag store.
// Patch target is the strb instruction at pattern + 12:
//   strb w8,  [x24, #0x30] -> strb wzr, [x24, #0x30]
constexpr int kInfoRequiredFlagPattern[] = {
    0xE8, 0x03, 0x6C, 0x39,
    0x28, 0xA1, 0x00, 0x34,
    0xE8, 0x03, 0x6B, 0x39,
    0x08, 0xC3, 0x00, 0x39,
    0xA8, 0xE3, 0x03, 0xD1,
    0xE0, 0x03, 0x14, 0xAA,
};
constexpr size_t kInfoRequiredFlagPatternSize = sizeof(kInfoRequiredFlagPattern) / sizeof(kInfoRequiredFlagPattern[0]);
constexpr size_t kInfoRequiredFlagStoreOffset = 12;
constexpr uint32_t kInfoRequiredFlagStoreOriginal = 0x3900C308u;
constexpr uint32_t kInfoRequiredFlagStoreForcedFalse = 0x3900C31Fu;

// Minecraft Bedrock Android 26.23 ARM64.
// ResourcePackStackPacket::_read required/server-forced style flag store.
// Patch target is the strb instruction at pattern + 8:
//   strb w8,  [x21, #0x68] -> strb wzr, [x21, #0x68]
constexpr int kStackRequiredFlagPattern[] = {
    0xE8, 0x43, 0x49, 0x39,
    0xF7, 0x03, 0x15, 0xAA,
    0xA8, 0xA2, 0x01, 0x39,
    0xA8, 0xE9, 0x02, 0xD0,
    0x08, 0x81, 0x3D, 0x91,
    0xA9, 0x03, 0x04, 0xD1,
};
constexpr size_t kStackRequiredFlagPatternSize = sizeof(kStackRequiredFlagPattern) / sizeof(kStackRequiredFlagPattern[0]);
constexpr size_t kStackRequiredFlagStoreOffset = 8;
constexpr uint32_t kStackRequiredFlagStoreOriginal = 0x3901A2A8u;
constexpr uint32_t kStackRequiredFlagStoreForcedFalse = 0x3901A2BFu;

struct ExecSegment {
    uintptr_t start = 0;
    size_t size = 0;
};

struct ModuleInfo {
    uintptr_t base = 0;
    std::vector<ExecSegment> execSegments;
};

std::atomic<bool> g_workerStarted{false};

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
        if (phdr.p_type != PT_LOAD || (phdr.p_flags & PF_X) == 0) {
            continue;
        }
        ExecSegment seg;
        seg.start = out->base + static_cast<uintptr_t>(phdr.p_vaddr);
        seg.size = static_cast<size_t>(phdr.p_memsz);
        out->execSegments.push_back(seg);
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

bool patchSingleInstruction(
    const ModuleInfo& module,
    const int* pattern,
    size_t patternSize,
    size_t patchOffset,
    uint32_t expectedOriginal,
    uint32_t patchedInstruction
) {
    std::vector<uintptr_t> matches = scanAllExecutableSegments(module, pattern, patternSize);
    if (matches.size() != 1) return false;

    void* patchAddr = reinterpret_cast<void*>(matches[0] + patchOffset);
    const uint32_t current = readU32(patchAddr);
    if (current == patchedInstruction) return true;
    if (current != expectedOriginal) return false;

    if (!setPageProtection(patchAddr, sizeof(uint32_t), PROT_READ | PROT_WRITE | PROT_EXEC)) {
        return false;
    }

    writeU32(patchAddr, patchedInstruction);
    flushInstructionCache(patchAddr, sizeof(uint32_t));

    setPageProtection(patchAddr, sizeof(uint32_t), PROT_READ | PROT_EXEC);
    return readU32(patchAddr) == patchedInstruction;
}

void applyPatches(const ModuleInfo& module) {
    patchSingleInstruction(
        module,
        kInfoRequiredFlagPattern,
        kInfoRequiredFlagPatternSize,
        kInfoRequiredFlagStoreOffset,
        kInfoRequiredFlagStoreOriginal,
        kInfoRequiredFlagStoreForcedFalse
    );

    patchSingleInstruction(
        module,
        kStackRequiredFlagPattern,
        kStackRequiredFlagPatternSize,
        kStackRequiredFlagStoreOffset,
        kStackRequiredFlagStoreOriginal,
        kStackRequiredFlagStoreForcedFalse
    );
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
