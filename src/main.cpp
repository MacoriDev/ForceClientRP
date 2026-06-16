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

constexpr uint8_t kBuildId_26_23[] = {
    0x3e, 0x61, 0x89, 0xba, 0x1d, 0x83, 0x57, 0xef, 0x50, 0x0d,
    0x80, 0x43, 0xbc, 0x55, 0x14, 0x06, 0xf0, 0xaa, 0xe4, 0x55,
};

constexpr uint8_t kBuildId_26_30[] = {
    0x2d, 0xd6, 0xf4, 0x53, 0xb4, 0xcf, 0xad, 0xea, 0x91, 0xa3,
    0x5e, 0x49, 0x8a, 0x10, 0x55, 0x60, 0x1a, 0x22, 0x85, 0x0a,
};

struct BytePattern {
    const int* bytes = nullptr;
    size_t size = 0;
};

struct PatchSpec {
    BytePattern pattern;
    size_t patchOffset = 0;
    uint32_t expectedOriginal = 0;
    uint32_t patchedInstruction = 0;
};

// Minecraft Bedrock Android 26.23 ARM64, build-id 3e6189ba1d8357ef500d8043bc551406f0aae455.
// ResourcePacksInfoPacket::_read required/must-accept flag store.
//   strb w8,  [x24, #0x30] -> strb wzr, [x24, #0x30]
constexpr int kInfoRequiredFlagPattern_26_23[] = {
    0xE8, 0x03, 0x6C, 0x39,
    0x28, 0xA1, 0x00, 0x34,
    0xE8, 0x03, 0x6B, 0x39,
    0x08, 0xC3, 0x00, 0x39,
    0xA8, 0xE3, 0x03, 0xD1,
    0xE0, 0x03, 0x14, 0xAA,
};
constexpr size_t kInfoRequiredFlagStoreOffset_26_23 = 12;
constexpr uint32_t kInfoRequiredFlagStoreOriginal_26_23 = 0x3900C308u;
constexpr uint32_t kInfoRequiredFlagStoreForcedFalse_26_23 = 0x3900C31Fu;

// Minecraft Bedrock Android 26.23 ARM64, build-id 3e6189ba1d8357ef500d8043bc551406f0aae455.
// ResourcePackStackPacket::_read required/server-forced style flag store.
//   strb w8,  [x21, #0x68] -> strb wzr, [x21, #0x68]
constexpr int kStackRequiredFlagPattern_26_23[] = {
    0xE8, 0x43, 0x49, 0x39,
    0xF7, 0x03, 0x15, 0xAA,
    0xA8, 0xA2, 0x01, 0x39,
    0xA8, 0xE9, 0x02, 0xD0,
    0x08, 0x81, 0x3D, 0x91,
    0xA9, 0x03, 0x04, 0xD1,
};
constexpr size_t kStackRequiredFlagStoreOffset_26_23 = 8;
constexpr uint32_t kStackRequiredFlagStoreOriginal_26_23 = 0x3901A2A8u;
constexpr uint32_t kStackRequiredFlagStoreForcedFalse_26_23 = 0x3901A2BFu;

constexpr PatchSpec kPatches_26_23[] = {
    {{kInfoRequiredFlagPattern_26_23, sizeof(kInfoRequiredFlagPattern_26_23) / sizeof(kInfoRequiredFlagPattern_26_23[0])},
     kInfoRequiredFlagStoreOffset_26_23,
     kInfoRequiredFlagStoreOriginal_26_23,
     kInfoRequiredFlagStoreForcedFalse_26_23},
    {{kStackRequiredFlagPattern_26_23, sizeof(kStackRequiredFlagPattern_26_23) / sizeof(kStackRequiredFlagPattern_26_23[0])},
     kStackRequiredFlagStoreOffset_26_23,
     kStackRequiredFlagStoreOriginal_26_23,
     kStackRequiredFlagStoreForcedFalse_26_23},
};


// Minecraft Bedrock Android 26.30 ARM64, build-id 2dd6f453b4cfadea91a35e498a1055601a22850a.
// ResourcePacksInfoPacket::_read required/must-accept flag store.
//   strb w8,  [x28, #0x30] -> strb wzr, [x28, #0x30]
constexpr int kInfoRequiredFlagPattern_26_30[] = {
    0xA8, 0x03, 0x54, 0x38,
    0xE8, 0xC3, 0x29, 0x39,
    0xA8, 0x17, 0x00, 0x34,
    0xA8, 0x03, 0x50, 0x38,
    0xE8, 0xC3, 0x28, 0x39,
    0x88, 0xC3, 0x00, 0x39,
    0xA8, 0x03, 0x04, 0xD1,
    0xE0, 0x03, 0x14, 0xAA,
};
constexpr size_t kInfoRequiredFlagStoreOffset_26_30 = 20;
constexpr uint32_t kInfoRequiredFlagStoreOriginal_26_30 = 0x3900C388u;
constexpr uint32_t kInfoRequiredFlagStoreForcedFalse_26_30 = 0x3900C39Fu;

// Minecraft Bedrock Android 26.30 ARM64, build-id 2dd6f453b4cfadea91a35e498a1055601a22850a.
// ResourcePackStackPacket::_read required/server-forced style flag store.
//   strb w8,  [x20, #0x68] -> strb wzr, [x20, #0x68]
constexpr int kStackRequiredFlagPattern_26_30[] = {
    0xE8, 0x43, 0x57, 0x39,
    0x48, 0xEE, 0xFF, 0x34,
    0xE8, 0xC3, 0x59, 0x39,
    0xC8, 0x3D, 0x00, 0x34,
    0xE8, 0xC3, 0x58, 0x39,
    0x88, 0xA2, 0x01, 0x39,
    0xA8, 0x83, 0x01, 0xD1,
    0xE0, 0x03, 0x15, 0xAA,
};
constexpr size_t kStackRequiredFlagStoreOffset_26_30 = 20;
constexpr uint32_t kStackRequiredFlagStoreOriginal_26_30 = 0x3901A288u;
constexpr uint32_t kStackRequiredFlagStoreForcedFalse_26_30 = 0x3901A29Fu;

constexpr PatchSpec kPatches_26_30[] = {
    {{kInfoRequiredFlagPattern_26_30, sizeof(kInfoRequiredFlagPattern_26_30) / sizeof(kInfoRequiredFlagPattern_26_30[0])},
     kInfoRequiredFlagStoreOffset_26_30,
     kInfoRequiredFlagStoreOriginal_26_30,
     kInfoRequiredFlagStoreForcedFalse_26_30},
    {{kStackRequiredFlagPattern_26_30, sizeof(kStackRequiredFlagPattern_26_30) / sizeof(kStackRequiredFlagPattern_26_30[0])},
     kStackRequiredFlagStoreOffset_26_30,
     kStackRequiredFlagStoreOriginal_26_30,
     kStackRequiredFlagStoreForcedFalse_26_30},
};

struct ExecSegment {
    uintptr_t start = 0;
    size_t size = 0;
};

struct ModuleInfo {
    uintptr_t base = 0;
    std::vector<ExecSegment> execSegments;
    std::vector<uint8_t> buildId;
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

uintptr_t align4(uintptr_t value) {
    return (value + 3u) & ~static_cast<uintptr_t>(3u);
}

void readBuildIdFromNote(const uint8_t* begin, size_t size, std::vector<uint8_t>& out) {
    if (!begin || size < 16 || !out.empty()) return;

    uintptr_t cursor = reinterpret_cast<uintptr_t>(begin);
    const uintptr_t end = cursor + size;
    while (cursor + 12 <= end) {
        uint32_t namesz = 0;
        uint32_t descsz = 0;
        uint32_t type = 0;
        std::memcpy(&namesz, reinterpret_cast<const void*>(cursor), sizeof(namesz));
        std::memcpy(&descsz, reinterpret_cast<const void*>(cursor + 4), sizeof(descsz));
        std::memcpy(&type, reinterpret_cast<const void*>(cursor + 8), sizeof(type));
        cursor += 12;

        const uintptr_t nameStart = cursor;
        const uintptr_t nameEnd = nameStart + namesz;
        const uintptr_t descStart = align4(nameEnd);
        const uintptr_t descEnd = descStart + descsz;
        if (nameEnd > end || descEnd > end || descStart > end) break;

        const char* name = reinterpret_cast<const char*>(nameStart);
        if (type == 3 && namesz >= 3 && std::memcmp(name, "GNU", 3) == 0 && descsz > 0) {
            const uint8_t* desc = reinterpret_cast<const uint8_t*>(descStart);
            out.assign(desc, desc + descsz);
            return;
        }
        cursor = align4(descEnd);
    }
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
        } else if (phdr.p_type == PT_NOTE) {
            const auto* note = reinterpret_cast<const uint8_t*>(out->base + static_cast<uintptr_t>(phdr.p_vaddr));
            readBuildIdFromNote(note, static_cast<size_t>(phdr.p_memsz), out->buildId);
        }
    }
    return 1;
}

bool findTargetModule(ModuleInfo& info) {
    info = ModuleInfo{};
    dl_iterate_phdr(phdrCallback, &info);
    return info.base != 0 && !info.execSegments.empty();
}

bool buildIdEquals(const ModuleInfo& module, const uint8_t* expected, size_t expectedSize) {
    return module.buildId.size() == expectedSize && std::memcmp(module.buildId.data(), expected, expectedSize) == 0;
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

bool patchSingleInstruction(const ModuleInfo& module, const PatchSpec& spec) {
    std::vector<uintptr_t> matches = scanAllExecutableSegments(module, spec.pattern.bytes, spec.pattern.size);
    if (matches.size() != 1) return false;

    void* patchAddr = reinterpret_cast<void*>(matches[0] + spec.patchOffset);
    const uint32_t current = readU32(patchAddr);
    if (current == spec.patchedInstruction) return true;
    if (current != spec.expectedOriginal) return false;

    if (!setPageProtection(patchAddr, sizeof(uint32_t), PROT_READ | PROT_WRITE | PROT_EXEC)) {
        return false;
    }

    writeU32(patchAddr, spec.patchedInstruction);
    flushInstructionCache(patchAddr, sizeof(uint32_t));

    setPageProtection(patchAddr, sizeof(uint32_t), PROT_READ | PROT_EXEC);
    return readU32(patchAddr) == spec.patchedInstruction;
}

void applyPatchList(const ModuleInfo& module, const PatchSpec* patches, size_t count) {
    for (size_t i = 0; i < count; ++i) {
        patchSingleInstruction(module, patches[i]);
    }
}

void applyPatches(const ModuleInfo& module) {
    if (buildIdEquals(module, kBuildId_26_30, sizeof(kBuildId_26_30))) {
        applyPatchList(module, kPatches_26_30, sizeof(kPatches_26_30) / sizeof(kPatches_26_30[0]));
        return;
    }

    if (buildIdEquals(module, kBuildId_26_23, sizeof(kBuildId_26_23))) {
        applyPatchList(module, kPatches_26_23, sizeof(kPatches_26_23) / sizeof(kPatches_26_23[0]));
        return;
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
