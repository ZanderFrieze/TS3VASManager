// MapViewTypeTracker.cpp
// ─────────────────────────────────────────────────────────────────────────────
// See MapViewTypeTracker.h for design notes.
// ─────────────────────────────────────────────────────────────────────────────

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <cstdint>
#include <cstring>
#include <cstdio>
#include <algorithm>

#include "MapViewTypeTracker.h"
#include "Logger.h"

// ── Singleton storage ─────────────────────────────────────────────────────────
MapViewTypeTracker* MapViewTypeTracker::s_instance = nullptr;

static char s_storage[sizeof(MapViewTypeTracker)];

MapViewTypeTracker* MapViewTypeTracker::GetInstance() { return s_instance; }

void MapViewTypeTracker::Initialize() {
    if (!s_instance) {
        s_instance = new (s_storage) MapViewTypeTracker();
    }
}

void MapViewTypeTracker::Shutdown() {
    if (s_instance) {
        s_instance->~MapViewTypeTracker();
        s_instance = nullptr;
    }
}

// ── Constructor / destructor ──────────────────────────────────────────────────
MapViewTypeTracker::MapViewTypeTracker() {
    memset(m_typeTable, 0, sizeof(m_typeTable));
    memset(m_files,     0, sizeof(m_files));
    memset(m_allowIds,  0, sizeof(m_allowIds));
    InitializeCriticalSection(&m_cs);
    m_csInit = true;
}

MapViewTypeTracker::~MapViewTypeTracker() {
    if (m_csInit) {
        DeleteCriticalSection(&m_cs);
        m_csInit = false;
    }
}

// ── Known DBPF type name table ────────────────────────────────────────────────
// Maps Sims 3 DBPF resource type IDs to readable names for the view inventory.
// Unknown IDs fall through to the hex formatter.

struct KnownType { uint32_t typeId; const char* name; };
// Authoritative names from EA's GameData/Shared/DeltaPackages/*.cfg FileType
// table (every EP/SP delta ships the same map).  The previous table had several
// community-guessed IDs that were demonstrably wrong against this source — e.g.
// 0x220557DA is "stbl" (not "OBJK"), 0x2F7D0004 is "png" (not "LDES") — and was
// missing script/xml entirely.  Unknown IDs fall through to the hex formatter.
static const KnownType k_knownTypes[] = {
    // GPU-resident meshes/shaders.
    { 0x015A1849u, "geom"        },
    { 0x01D0E75Du, "mlod"        },
    { 0x01661233u, "modl"        },
    { 0x3453CF95u, "shaderdata"  },
    { 0x1C4A276Cu, "shadercache" },
    { 0x0418FE2Au, "boneweight"  },
    // ── Scripts / tuning ──
    { 0x0175e5cdu, "script"      },   // compiled .NET script (the real script type)
    { 0x0175e5d9u, "scriptsym"   },   // script debug symbols
    { 0x073faa07u, "s3sa_mod"    },   // modder script archive (NRaas et al.)
    { 0x0333406cu, "xml"         },   // XML tuning (previously mislabeled "S3SA")
    { 0x03b33ddfu, "tun"         },
    // ── Textures / images ──
    { 0x00b2d882u, "dds"         },
    { 0x2f7d0006u, "tga"         },
    { 0x2f7d0004u, "png"         },
    { 0x2f7d0002u, "jpg"         },
    { 0x00b552eau, "spt"         },
    { 0x021d7e8cu, "spt2"        },
    { 0x03b4c61du, "lightingdata"},
    { 0xd55f7cafu, "lightrigs"   },
    { 0xea5118b0u, "swb"         },
    // ── Animation / rig ──
    { 0x8eaf13deu, "rig"         },
    { 0x6b20c4f3u, "clip"        },
    // ── Sim / catalog / layout / strings ──
    { 0x025ed6f4u, "simoutfit"   },
    { 0xf0ff5598u, "triggers"    },
    { 0x11c258c0u, "ctriggers"   },
    { 0xd3044521u, "slot"        },
    { 0x1f886eadu, "ini"         },
    { 0x025c95b6u, "layout"      },
    { 0x025c90a6u, "css"         },
    { 0x220557dau, "stbl"        },   // string table
    // ── Audio ──
    { 0x02b9f662u, "prop"        },
    { 0x010077c4u, "wav"         },
    { 0x010077bbu, "mp3"         },
    { 0x010077cau, "xa"          },
    { 0x01a527dbu, "snr"         },
    { 0x01eef63au, "sns"         },
    { 0x0181b0d2u, "abk"         },
    { 0x02c9eff2u, "submix"      },
    { 0x029e333bu, "voice"       },
    { 0x00000000u, nullptr       },   // sentinel
};

const char* DbpfTypeName(uint32_t typeId) {
    static char buf[12];
    for (int i = 0; k_knownTypes[i].name != nullptr; ++i) {
        if (k_knownTypes[i].typeId == typeId)
            return k_knownTypes[i].name;
    }
    sprintf_s(buf, "0x%08X", typeId);
    return buf;
}

// ── RecordView ────────────────────────────────────────────────────────────────
void MapViewTypeTracker::RecordView(ViewKind kind, const char* baseName,
                                    uint64_t viewBytes, bool redirected)
{
    switch (kind) {
    case ViewKind::Anonymous:
        InterlockedIncrement64(&m_cntAnonymous);
        InterlockedAdd64(&m_bytesAnonymous, (LONG64)viewBytes);
        break;
    case ViewKind::ImageSection:
        InterlockedIncrement64(&m_cntImage);
        InterlockedAdd64(&m_bytesImage, (LONG64)viewBytes);
        break;
    case ViewKind::FileMappedOther:
        InterlockedIncrement64(&m_cntOtherFile);
        InterlockedAdd64(&m_bytesOtherFile, (LONG64)viewBytes);
        if (baseName && baseName[0])
            RecordFileName(baseName, viewBytes);
        break;
    case ViewKind::FileMappedNoName:
        InterlockedIncrement64(&m_cntNoName);
        InterlockedAdd64(&m_bytesNoName, (LONG64)viewBytes);
        break;
    case ViewKind::FileMappedPackage:
        InterlockedIncrement64(&m_cntPkgNoDbpf);
        InterlockedAdd64(&m_bytesPkgNoDbpf, (LONG64)viewBytes);
        if (baseName && baseName[0])
            RecordFileName(baseName, viewBytes);
        break;
    case ViewKind::FileMappedDbpf:
        InterlockedIncrement64(&m_cntPkgDbpf);
        InterlockedAdd64(&m_bytesPkgDbpf, (LONG64)viewBytes);
        if (baseName && baseName[0])
            RecordFileName(baseName, viewBytes);
        break;
    }

    if (redirected) {
        InterlockedIncrement64(&m_cntRedirected);
        InterlockedAdd64(&m_bytesRedirected, (LONG64)viewBytes);
    }
}

// ── RecordDbpfTypes ───────────────────────────────────────────────────────────
void MapViewTypeTracker::RecordDbpfTypes(const DbpfTypeStats* typeStats, uint32_t count)
{
    if (!typeStats || count == 0) return;

    // The CS only guards slot insertion; Interlocked ops handle counter updates.
    EnterCriticalSection(&m_cs);
    for (uint32_t i = 0; i < count; ++i) {
        TypeSlot* slot = FindOrInsertType(typeStats[i].typeId);
        if (slot) {
            InterlockedAdd64(&slot->entryCount, (LONG64)typeStats[i].entryCount);
            InterlockedAdd64(&slot->totalBytes, (LONG64)typeStats[i].totalMemBytes);
            InterlockedIncrement64(&slot->viewCount);
        }
    }
    LeaveCriticalSection(&m_cs);
}

// ── AddRedirectTypeId / ClearRedirectTypeIds / ShouldRedirect ─────────────────
void MapViewTypeTracker::AddRedirectTypeId(uint32_t typeId) {
    EnterCriticalSection(&m_cs);
    if (m_allowCount < kMaxAllowIds) {
        // Deduplicate
        for (int i = 0; i < m_allowCount; ++i)
            if (m_allowIds[i] == typeId) { LeaveCriticalSection(&m_cs); return; }
        m_allowIds[m_allowCount++] = typeId;
    }
    LeaveCriticalSection(&m_cs);
}

void MapViewTypeTracker::ClearRedirectTypeIds() {
    EnterCriticalSection(&m_cs);
    m_allowCount = 0;
    LeaveCriticalSection(&m_cs);
}

bool MapViewTypeTracker::ShouldRedirect(const DbpfTypeStats* typeStats, uint32_t count) const
{
    // Empty allow-list → redirect everything (current / default behaviour).
    if (m_allowCount == 0) return true;

    // Non-empty allow-list → redirect only if ANY type in this view matches.
    for (uint32_t i = 0; i < count; ++i) {
        for (int j = 0; j < m_allowCount; ++j) {
            if (typeStats[i].typeId == m_allowIds[j])
                return true;
        }
    }
    return false;
}

// ── Report ────────────────────────────────────────────────────────────────────
void MapViewTypeTracker::Report(const char* logTag)
{
    Logger* log = Logger::GetInstance();
    if (!log) return;
    if (!logTag || !*logTag) logTag = "MAPVIEW_REPORT";

    // ── Summary line ──────────────────────────────────────────────────────────
    LONG64 totalViews = InterlockedCompareExchange64(&m_cntAnonymous,   0, 0)
                      + InterlockedCompareExchange64(&m_cntImage,       0, 0)
                      + InterlockedCompareExchange64(&m_cntOtherFile,   0, 0)
                      + InterlockedCompareExchange64(&m_cntNoName,      0, 0)
                      + InterlockedCompareExchange64(&m_cntPkgNoDbpf,   0, 0)
                      + InterlockedCompareExchange64(&m_cntPkgDbpf,     0, 0);
    LONG64 totalBytes = InterlockedCompareExchange64(&m_bytesAnonymous, 0, 0)
                      + InterlockedCompareExchange64(&m_bytesImage,     0, 0)
                      + InterlockedCompareExchange64(&m_bytesOtherFile, 0, 0)
                      + InterlockedCompareExchange64(&m_bytesNoName,    0, 0)
                      + InterlockedCompareExchange64(&m_bytesPkgNoDbpf, 0, 0)
                      + InterlockedCompareExchange64(&m_bytesPkgDbpf,   0, 0);

    log->NamedInfo(logTag, "=== NtMapViewOfSection inventory ===");
    log->NamedInfo(logTag, "Total views: %lld  total bytes: %lld MB",
                   totalViews, totalBytes / (1024 * 1024));

    log->NamedInfo(logTag, "  Anonymous (MEM_PRIVATE):       views=%lld  bytes=%lld MB",
        InterlockedCompareExchange64(&m_cntAnonymous,   0, 0),
        InterlockedCompareExchange64(&m_bytesAnonymous, 0, 0) / (1024*1024));
    log->NamedInfo(logTag, "  Image section (MEM_IMAGE):     views=%lld  bytes=%lld MB",
        InterlockedCompareExchange64(&m_cntImage,       0, 0),
        InterlockedCompareExchange64(&m_bytesImage,     0, 0) / (1024*1024));
    log->NamedInfo(logTag, "  File-backed, no name:          views=%lld  bytes=%lld MB",
        InterlockedCompareExchange64(&m_cntNoName,      0, 0),
        InterlockedCompareExchange64(&m_bytesNoName,    0, 0) / (1024*1024));
    log->NamedInfo(logTag, "  File-backed, other ext:        views=%lld  bytes=%lld MB",
        InterlockedCompareExchange64(&m_cntOtherFile,   0, 0),
        InterlockedCompareExchange64(&m_bytesOtherFile, 0, 0) / (1024*1024));
    log->NamedInfo(logTag, "  Package ext, no DBPF header:   views=%lld  bytes=%lld MB",
        InterlockedCompareExchange64(&m_cntPkgNoDbpf,   0, 0),
        InterlockedCompareExchange64(&m_bytesPkgNoDbpf, 0, 0) / (1024*1024));
    log->NamedInfo(logTag, "  Package ext, valid DBPF:       views=%lld  bytes=%lld MB",
        InterlockedCompareExchange64(&m_cntPkgDbpf,     0, 0),
        InterlockedCompareExchange64(&m_bytesPkgDbpf,   0, 0) / (1024*1024));
    log->NamedInfo(logTag, "  Phase2 redirected (stub):      views=%lld  bytes=%lld MB",
        InterlockedCompareExchange64(&m_cntRedirected,     0, 0),
        InterlockedCompareExchange64(&m_bytesRedirected,   0, 0) / (1024*1024));

    // ── DBPF type table — sorted by bytes descending ──────────────────────────
    // Snapshot under CS, then sort outside it.
    struct Snap { uint32_t typeId; LONG64 entries; LONG64 bytes; LONG64 views; };
    static Snap snaps[kTypeTableCap];
    int snapCount = 0;

    EnterCriticalSection(&m_cs);
    for (int i = 0; i < kTypeTableCap; ++i) {
        if (m_typeTable[i].typeId != 0) {
            snaps[snapCount].typeId  = m_typeTable[i].typeId;
            snaps[snapCount].entries = InterlockedCompareExchange64(&m_typeTable[i].entryCount, 0, 0);
            snaps[snapCount].bytes   = InterlockedCompareExchange64(&m_typeTable[i].totalBytes,  0, 0);
            snaps[snapCount].views   = InterlockedCompareExchange64(&m_typeTable[i].viewCount,   0, 0);
            ++snapCount;
        }
    }
    LeaveCriticalSection(&m_cs);

    // Sort by bytes descending
    std::sort(snaps, snaps + snapCount, [](const Snap& a, const Snap& b) {
        return a.bytes > b.bytes;
    });

    if (snapCount > 0) {
        log->NamedInfo(logTag, "DBPF type distribution (sorted by bytes desc):");
        log->NamedInfo(logTag, "  %-12s  %-8s  %10s  %8s  %6s",
                       "TypeID", "Name", "Entries", "Bytes MB", "Views");
        for (int i = 0; i < snapCount; ++i) {
            log->NamedInfo(logTag, "  0x%08X    %-8s  %10lld  %8lld  %6lld",
                           snaps[i].typeId,
                           DbpfTypeName(snaps[i].typeId),
                           snaps[i].entries,
                           snaps[i].bytes / (1024 * 1024),
                           snaps[i].views);
        }
    } else {
        log->NamedInfo(logTag, "DBPF type distribution: (no DBPF views seen)");
    }

    // ── Per-file table — sorted by bytes descending ───────────────────────────
    struct FileSnap { char name[80]; LONG64 views; LONG64 bytes; };
    static FileSnap fsnaps[kMaxFiles];
    int fCount = 0;

    EnterCriticalSection(&m_cs);
    fCount = m_fileCount;
    for (int i = 0; i < fCount; ++i) {
        strncpy_s(fsnaps[i].name, m_files[i].name, _TRUNCATE);
        fsnaps[i].views = InterlockedCompareExchange64(&m_files[i].viewCount,  0, 0);
        fsnaps[i].bytes = InterlockedCompareExchange64(&m_files[i].totalBytes, 0, 0);
    }
    LeaveCriticalSection(&m_cs);

    std::sort(fsnaps, fsnaps + fCount, [](const FileSnap& a, const FileSnap& b) {
        return a.bytes > b.bytes;
    });

    if (fCount > 0) {
        log->NamedInfo(logTag, "File-backed views by filename (top %d, sorted by bytes desc):", fCount);
        for (int i = 0; i < fCount; ++i) {
            log->NamedInfo(logTag, "  %-50s  views=%lld  bytes=%lld MB",
                           fsnaps[i].name, fsnaps[i].views,
                           fsnaps[i].bytes / (1024 * 1024));
        }
    }

    log->NamedInfo(logTag, "=== end MAPVIEW_REPORT ===");
}

// ── Internal: FindOrInsertType ────────────────────────────────────────────────
// Open-addressing hash table with linear probe.  MUST be called under m_cs.
MapViewTypeTracker::TypeSlot* MapViewTypeTracker::FindOrInsertType(uint32_t typeId)
{
    if (typeId == 0) return nullptr;
    uint32_t idx = (typeId ^ (typeId >> 16)) & (kTypeTableCap - 1);
    for (int probe = 0; probe < kTypeTableCap; ++probe) {
        uint32_t slot = (idx + probe) & (kTypeTableCap - 1);
        if (m_typeTable[slot].typeId == typeId)
            return &m_typeTable[slot];
        if (m_typeTable[slot].typeId == 0) {
            // Insert new entry
            m_typeTable[slot].typeId = typeId;
            m_typeTable[slot].entryCount = 0;
            m_typeTable[slot].totalBytes  = 0;
            m_typeTable[slot].viewCount   = 0;
            return &m_typeTable[slot];
        }
    }
    return nullptr;   // table full (should not happen with 256 slots for ~40 types)
}

// ── Internal: RecordFileName ──────────────────────────────────────────────────
// Case-insensitive linear search; inserts if not found and there's capacity.
// MUST be called WITHOUT m_cs held (takes it internally for insertion).
void MapViewTypeTracker::RecordFileName(const char* baseName, uint64_t bytes)
{
    if (!baseName || !baseName[0]) return;

    // Fast path: search without lock (reads are safe; worst case we double-insert
    // during a race which the insertion deduplicate guard below prevents).
    for (int i = 0; i < m_fileCount; ++i) {
        if (_stricmp(m_files[i].name, baseName) == 0) {
            InterlockedIncrement64(&m_files[i].viewCount);
            InterlockedAdd64(&m_files[i].totalBytes, (LONG64)bytes);
            return;
        }
    }

    // Not found — take lock and insert (check again to handle race).
    EnterCriticalSection(&m_cs);
    for (int i = 0; i < m_fileCount; ++i) {
        if (_stricmp(m_files[i].name, baseName) == 0) {
            InterlockedIncrement64(&m_files[i].viewCount);
            InterlockedAdd64(&m_files[i].totalBytes, (LONG64)bytes);
            LeaveCriticalSection(&m_cs);
            return;
        }
    }
    if (m_fileCount < kMaxFiles) {
        int slot = m_fileCount++;
        strncpy_s(m_files[slot].name, baseName, _TRUNCATE);
        m_files[slot].viewCount  = 1;
        m_files[slot].totalBytes = (LONG64)bytes;
    }
    LeaveCriticalSection(&m_cs);
}
