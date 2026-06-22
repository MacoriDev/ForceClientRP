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

#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, kTag, __VA_ARGS__)
#define LOGW(...) __android_log_print(ANDROID_LOG_WARN, kTag, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, kTag, __VA_ARGS__)

struct ExecSegment { uintptr_t start = 0; size_t size = 0; };
struct ModuleInfo { uintptr_t base = 0; std::vector<ExecSegment> execSegments; };
struct BytePattern { const int* bytes = nullptr; size_t size = 0; const char* name = nullptr; };

std::atomic<bool> g_workerStarted{false};

constexpr uint32_t kStrbUnsignedMask = 0xFFC00000u;
constexpr uint32_t kStrbUnsignedValue = 0x39000000u;
constexpr uint32_t kLdrbUnsignedMask = 0xFFC00000u;
constexpr uint32_t kLdrbUnsignedValue = 0x39400000u;

constexpr int kInfoLegacy[] = {
    0xE8, 0x03, 0x6C, 0x39, -1, -1, -1, 0x34,
    0xE8, 0x03, 0x6B, 0x39, -1, 0xC3, 0x00, 0x39,
    0xA8, 0xE3, 0x03, 0xD1, 0xE0, 0x03, 0x14, 0xAA,
};
constexpr int kStackLegacy[] = {
    0xE8, 0x43, 0x49, 0x39, 0xF7, 0x03, 0x15, 0xAA,
    -1, 0xA2, 0x01, 0x39, 0xA8, 0xE9, 0x02, 0xD0,
    0x08, 0x81, 0x3D, 0x91, 0xA9, 0x03, 0x04, 0xD1,
};
constexpr int kInfoModern[] = {
    0xA8, 0x03, 0x54, 0x38, 0xE8, 0xC3, 0x29, 0x39,
    -1, -1, -1, 0x34, 0xA8, 0x03, 0x50, 0x38,
    0xE8, 0xC3, 0x28, 0x39, -1, 0xC3, 0x00, 0x39,
    0xA8, 0x03, 0x04, 0xD1, 0xE0, 0x03, 0x14, 0xAA,
};
constexpr int kStackModern[] = {
    0xE8, 0x43, 0x57, 0x39, -1, -1, -1, 0x34,
    0xE8, 0xC3, 0x59, 0x39, -1, -1, -1, 0x34,
    0xE8, 0xC3, 0x58, 0x39, -1, 0xA2, 0x01, 0x39,
    0xA8, 0x83, 0x01, 0xD1, 0xE0, 0x03, 0x15, 0xAA,
};

bool contains(const char* haystack, const char* needle) {
    return haystack && needle && std::strstr(haystack, needle) != nullptr;
}

uint32_t readU32(const void* p) {
    uint32_t v = 0;
    std::memcpy(&v, p, sizeof(v));
    return v;
}

void writeU32(void* p, uint32_t v) {
    std::memcpy(p, &v, sizeof(v));
}

bool patternMatches(const uint8_t* ptr, const int* pattern, size_t size) {
    for (size_t i = 0; i < size; ++i) {
        if (pattern[i] >= 0 && ptr[i] != static_cast<uint8_t>(pattern[i])) return false;
    }
    return true;
}

std::vector<uintptr_t> scanAll(const ModuleInfo& module, const int* pattern, size_t size, size_t maxMatches = 8) {
    std::vector<uintptr_t> out;
    for (const auto& seg : module.execSegments) {
        if (seg.size < size) continue;
        const auto* b = reinterpret_cast<const uint8_t*>(seg.start);
        for (size_t i = 0; i <= seg.size - size; ++i) {
            if (patternMatches(b + i, pattern, size)) {
                out.push_back(seg.start + i);
                if (out.size() >= maxMatches) return out;
            }
        }
    }
    return out;
}

int phdrCallback(dl_phdr_info* info, size_t, void* data) {
    auto* out = static_cast<ModuleInfo*>(data);
    if (!info || !contains(info->dlpi_name, kTargetModule)) return 0;
    out->base = static_cast<uintptr_t>(info->dlpi_addr);
    for (int i = 0; i < info->dlpi_phnum; ++i) {
        const ElfW(Phdr)& ph = info->dlpi_phdr[i];
        if (ph.p_type == PT_LOAD && (ph.p_flags & PF_X) != 0) {
            out->execSegments.push_back({out->base + static_cast<uintptr_t>(ph.p_vaddr), static_cast<size_t>(ph.p_memsz)});
        }
    }
    return 1;
}

bool findTargetModule(ModuleInfo& out) {
    out = ModuleInfo{};
    dl_iterate_phdr(phdrCallback, &out);
    return out.base != 0 && !out.execSegments.empty();
}

bool inExecutable(const ModuleInfo& module, uintptr_t addr) {
    for (const auto& seg : module.execSegments) {
        if (addr >= seg.start && addr + 4 <= seg.start + seg.size) return true;
    }
    return false;
}

bool mprotectCode(void* addr, size_t len, int prot) {
    const long pageSize = sysconf(_SC_PAGESIZE);
    if (pageSize <= 0) return false;
    const uintptr_t mask = static_cast<uintptr_t>(pageSize) - 1;
    const uintptr_t start = reinterpret_cast<uintptr_t>(addr) & ~mask;
    const uintptr_t end = (reinterpret_cast<uintptr_t>(addr) + len + mask) & ~mask;
    return ::mprotect(reinterpret_cast<void*>(start), end - start, prot) == 0;
}

bool writeInstruction(const ModuleInfo& module, uintptr_t addr, uint32_t patched, const char* label) {
    if (!inExecutable(module, addr)) {
        LOGW("skip %s: addr not executable rva=0x%zx", label, static_cast<size_t>(addr - module.base));
        return false;
    }
    auto* p = reinterpret_cast<void*>(addr);
    const uint32_t old = readU32(p);
    if (old == patched) {
        LOGI("already patched %s rva=0x%zx", label, static_cast<size_t>(addr - module.base));
        return true;
    }
    if (!mprotectCode(p, sizeof(uint32_t), PROT_READ | PROT_WRITE | PROT_EXEC)) {
        LOGE("mprotect failed %s rva=0x%zx", label, static_cast<size_t>(addr - module.base));
        return false;
    }
    writeU32(p, patched);
    __builtin___clear_cache(reinterpret_cast<char*>(p), reinterpret_cast<char*>(p) + sizeof(uint32_t));
    mprotectCode(p, sizeof(uint32_t), PROT_READ | PROT_EXEC);
    const bool ok = readU32(p) == patched;
    LOGI("%s %s rva=0x%zx old=0x%08x new=0x%08x", ok ? "patched" : "patch failed", label, static_cast<size_t>(addr - module.base), old, patched);
    return ok;
}

uint32_t strbOffset(uint32_t ins) { return (ins >> 10u) & 0xFFFu; }
uint32_t ldrbOffset(uint32_t ins) { return (ins >> 10u) & 0xFFFu; }
uint32_t rn(uint32_t ins) { return (ins >> 5u) & 31u; }
uint32_t rt(uint32_t ins) { return ins & 31u; }
bool isStrb(uint32_t ins) { return (ins & kStrbUnsignedMask) == kStrbUnsignedValue; }
bool isLdrb(uint32_t ins) { return (ins & kLdrbUnsignedMask) == kLdrbUnsignedValue; }
uint32_t storeWzr(uint32_t ins) { return (ins & ~31u) | 31u; }
uint32_t movWRegZero(uint32_t reg) { return 0x52800000u | (reg & 31u); }

size_t patchStrbNear(const ModuleInfo& module, const char* label, uintptr_t anchor, intptr_t delta, size_t length, uint32_t baseReg, const uint32_t* offsets, size_t offsetCount) {
    if (!anchor) return 0;
    size_t patched = 0;
    uintptr_t start = static_cast<uintptr_t>(static_cast<intptr_t>(anchor) + delta) & ~static_cast<uintptr_t>(3);
    for (size_t off = 0; off + 4 <= length; off += 4) {
        uintptr_t addr = start + off;
        if (!inExecutable(module, addr)) continue;
        uint32_t ins = readU32(reinterpret_cast<const void*>(addr));
        if (!isStrb(ins) || rn(ins) != baseReg) continue;
        const uint32_t imm = strbOffset(ins);
        bool wanted = false;
        for (size_t i = 0; i < offsetCount; ++i) wanted |= offsets[i] == imm;
        if (!wanted) continue;
        char name[96]{};
        snprintf(name, sizeof(name), "%s x%u#0x%x", label, baseReg, imm);
        if (writeInstruction(module, addr, storeWzr(ins), name)) ++patched;
    }
    LOGI("group %s patched count=%zu", label, patched);
    return patched;
}

size_t patchPacketFlags(const ModuleInfo& module) {
    size_t patched = 0;

    auto legacyInfo = scanAll(module, kInfoLegacy, sizeof(kInfoLegacy) / sizeof(kInfoLegacy[0]), 4);
    LOGI("pattern legacy-info match count=%zu", legacyInfo.size());
    if (legacyInfo.size() == 1) {
        uintptr_t addr = legacyInfo[0] + 12;
        uint32_t ins = readU32(reinterpret_cast<const void*>(addr));
        if (isStrb(ins) && strbOffset(ins) == 0x30 && writeInstruction(module, addr, storeWzr(ins), "legacy info #0x30")) ++patched;
    }

    auto legacyStack = scanAll(module, kStackLegacy, sizeof(kStackLegacy) / sizeof(kStackLegacy[0]), 4);
    LOGI("pattern legacy-stack match count=%zu", legacyStack.size());
    if (legacyStack.size() == 1) {
        uintptr_t addr = legacyStack[0] + 8;
        uint32_t ins = readU32(reinterpret_cast<const void*>(addr));
        if (isStrb(ins) && strbOffset(ins) == 0x68 && writeInstruction(module, addr, storeWzr(ins), "legacy stack #0x68")) ++patched;
    }

    auto info = scanAll(module, kInfoModern, sizeof(kInfoModern) / sizeof(kInfoModern[0]), 4);
    LOGI("pattern modern-info match count=%zu", info.size());
    for (auto m : info) LOGI("pattern modern-info match rva=0x%zx", static_cast<size_t>(m - module.base));
    if (info.size() == 1) {
        constexpr uint32_t offsets[] = {0x30, 0x31, 0x32, 0x33, 0x60};
        patched += patchStrbNear(module, "modern info", info[0], 0, 0x220, 28, offsets, sizeof(offsets) / sizeof(offsets[0]));
    }

    auto stack = scanAll(module, kStackModern, sizeof(kStackModern) / sizeof(kStackModern[0]), 4);
    LOGI("pattern modern-stack match count=%zu", stack.size());
    for (auto m : stack) LOGI("pattern modern-stack match rva=0x%zx", static_cast<size_t>(m - module.base));
    if (stack.size() == 1) {
        constexpr uint32_t offsets[] = {0x54, 0x68, 0xD8, 0xD9};
        patched += patchStrbNear(module, "modern stack", stack[0], -0x420, 0x980, 20, offsets, sizeof(offsets) / sizeof(offsets[0]));
    }
    return patched;
}

uintptr_t findCString(const ModuleInfo& module, const char* needle) {
    const size_t n = std::strlen(needle);
    for (const auto& seg : module.execSegments) {
        if (seg.size <= n) continue;
        const auto* b = reinterpret_cast<const uint8_t*>(seg.start);
        for (size_t i = 0; i + n < seg.size; ++i) {
            if (b[i + n] == 0 && std::memcmp(b + i, needle, n) == 0) return seg.start + i;
        }
    }
    return 0;
}

int64_t signExtend(int64_t value, unsigned bits) {
    const int64_t mask = 1LL << (bits - 1);
    return (value ^ mask) - mask;
}

std::vector<uintptr_t> findAdrpAddXrefs(const ModuleInfo& module, uintptr_t target, size_t maxMatches = 8) {
    std::vector<uintptr_t> out;
    const uintptr_t targetPage = target & ~static_cast<uintptr_t>(0xFFF);
    for (const auto& seg : module.execSegments) {
        for (size_t off = 0; off + 32 < seg.size; off += 4) {
            uintptr_t pc = seg.start + off;
            uint32_t adrp = readU32(reinterpret_cast<const void*>(pc));
            if ((adrp & 0x9F000000u) != 0x90000000u) continue;
            uint32_t reg = adrp & 31u;
            int64_t imm = static_cast<int64_t>(((adrp >> 5u) & 0x7FFFFu) << 2u | ((adrp >> 29u) & 3u));
            imm = signExtend(imm, 21);
            uintptr_t page = (pc & ~static_cast<uintptr_t>(0xFFF)) + static_cast<intptr_t>(imm << 12);
            if (page != targetPage) continue;
            for (int look = 1; look <= 7; ++look) {
                uintptr_t pc2 = pc + static_cast<uintptr_t>(look * 4);
                uint32_t add = readU32(reinterpret_cast<const void*>(pc2));
                if ((add & 0xFFC00000u) != 0x91000000u) continue;
                if (((add >> 5u) & 31u) != reg) continue;
                uint32_t imm12 = (add >> 10u) & 0xFFFu;
                uint32_t shift = (add >> 22u) & 3u;
                uintptr_t addr = page + (static_cast<uintptr_t>(imm12) << (shift ? 12 : 0));
                if (addr == target) {
                    out.push_back(pc);
                    if (out.size() >= maxMatches) return out;
                }
            }
        }
    }
    return out;
}

size_t patchServerRequiredSessionFlag(const ModuleInfo& module) {
    uintptr_t str = findCString(module, "resource_pack_download_server_required");
    if (!str) {
        LOGI("server-required string not found");
        return 0;
    }
    LOGI("server-required string rva=0x%zx", static_cast<size_t>(str - module.base));
    auto refs = findAdrpAddXrefs(module, str, 4);
    LOGI("server-required xref count=%zu", refs.size());
    size_t patched = 0;
    for (uintptr_t ref : refs) {
        LOGI("server-required xref rva=0x%zx", static_cast<size_t>(ref - module.base));
        uintptr_t start = ref > 0x120 ? ref - 0x120 : ref;
        for (uintptr_t addr = start; addr + 4 <= ref; addr += 4) {
            if (!inExecutable(module, addr)) continue;
            uint32_t ins = readU32(reinterpret_cast<const void*>(addr));
            if (!isLdrb(ins)) continue;
            if (rn(ins) != 22 || ldrbOffset(ins) != 0x58) continue;
            char label[96]{};
            snprintf(label, sizeof(label), "server-required session flag x22#0x58 -> w%u=0", rt(ins));
            if (writeInstruction(module, addr, movWRegZero(rt(ins)), label)) ++patched;
        }
    }
    LOGI("server-required session flag patched count=%zu", patched);
    return patched;
}

void applyPatches(const ModuleInfo& module) {
    LOGI("module base=%p execSegments=%zu", reinterpret_cast<void*>(module.base), module.execSegments.size());
    for (const auto& seg : module.execSegments) LOGI("exec segment rva=0x%zx size=0x%zx", static_cast<size_t>(seg.start - module.base), seg.size);
    size_t total = 0;
    total += patchPacketFlags(module);
    total += patchServerRequiredSessionFlag(module);
    LOGI("patch summary totalPatched=%zu", total);
}

void* workerThread(void*) {
    LOGI("module loaded, worker started, V14 session-stack diagnostic build");
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
