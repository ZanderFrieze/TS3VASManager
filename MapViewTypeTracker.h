#pragma once
// MapViewTypeTracker.h  (TS3VASManager.dll — 32-bit, in-game)
// ─────────────────────────────────────────────────────────────────────────────
// Collects a complete inventory of every NtMapViewOfSection call seen by the
// hook, broken down by:
//
//   • View category  — anonymous, MEM_IMAGE, file-backed non-package,
//                      file-backed package (with/without valid DBPF header)
//   • DBPF type ID   — per-typeId entry count + cumulative bytes for every
//                      resource type seen inside .package / .world / .sims3
//                      views.  Sorted by bytes descending in the report.
//   • Per-file stats — top N distinct filenames (base name), with view count
//                      and cumulative bytes.
//
// Two outputs:
//   Report()        — called at shutdown or on demand; logs full table to
//                     Logger under the tag "MAPVIEW_REPORT".
//   ShouldRedirect()— optional type-ID allow-list gate used by Phase 2.
//                     When the allow-list is empty (default) every package
//                     view is redirected, matching current behaviour.
//                     Populate via AddRedirectTypeId() to restrict redirects
//                     to specific resource types (e.g. geometry + textures
//                     only) before Phase 2 runs.
//
// Thread-safe via a single CRITICAL_SECTION.  All counters are LONG64 updated
// through InterlockedAdd64; the CRITICAL_SECTION is only held during the
// DBPF slot-lookup (O(n) over ≤256 unique type IDs).
//
// Usage in WorkingHooks.cpp:
//   After the real NtMapViewOfSection returns, call RecordView() regardless
//   of extension.  For package views after ScanDbpfIndex(), also call
//   RecordDbpfTypes().  At shutdown call Report().
// ─────────────────────────────────────────────────────────────────────────────

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <cstdint>

// ── Per-type stats (returned by ScanDbpfIndex, stored internally) ─────────────
struct DbpfTypeStats {
    uint32_t typeId;
    uint32_t entryCount;      // number of DBPF index entries of this type
    uint64_t totalMemBytes;   // sum of DbpfIndexEntry.memSize for this type
};

// ── Known DBPF type name table (for human-readable report) ───────────────────
// Returns a short string like "GEOM", "TXTR", or "0x01234567" for unknowns.
const char* DbpfTypeName(uint32_t typeId);

// ────────────────────────────────────────────────────────────────────────────

class MapViewTypeTracker {
public:
    // ── Singleton lifecycle ───────────────────────────────────────────────────
    static MapViewTypeTracker* GetInstance();
    static void                Initialize();
    static void                Shutdown();

    // ── Per-view recording (call once per NtMapViewOfSection success) ─────────
    enum class ViewKind : uint8_t {
        Anonymous,          // mbi.Type == MEM_PRIVATE (no file name)
        ImageSection,       // mbi.Type == MEM_IMAGE   (PE / SEC_IMAGE)
        FileMappedOther,    // MEM_MAPPED, GetMappedFileName succeeded, NOT a package ext
        FileMappedNoName,   // MEM_MAPPED, GetMappedFileName failed
        FileMappedPackage,  // .package / .world / .sims3  — NO valid DBPF header
        FileMappedDbpf,     // .package / .world / .sims3  — valid DBPF header found
    };

    // Record a single view.  baseName may be "" for anonymous / no-name views.
    // viewBytes is *ViewSize.  redirected=true when Phase 2 swapped the view
    // for a proxy stub.  Call before RecordDbpfTypes for the same view.
    void RecordView(ViewKind kind, const char* baseName,
                    uint64_t viewBytes, bool redirected);

    // Record DBPF type distribution from ScanDbpfIndex output.
    // typeStats / count come directly from ScanDbpfIndex's return values.
    void RecordDbpfTypes(const DbpfTypeStats* typeStats, uint32_t count);

    // ── Type-ID redirect filter ───────────────────────────────────────────────
    // When the allow-list is empty (default), ShouldRedirect() returns true
    // for every package view → identical to current behaviour.
    //
    // Add type IDs to the allow-list to restrict Phase 2 redirects to only
    // views that contain at least one matching resource type.
    //
    // Example: redirect only geometry + texture views to save VAS while
    // leaving XML / script views as ordinary file-backed mappings.
    void  AddRedirectTypeId(uint32_t typeId);
    void  ClearRedirectTypeIds();
    bool  ShouldRedirect(const DbpfTypeStats* typeStats, uint32_t count) const;

    // ── Report ────────────────────────────────────────────────────────────────
    // Writes a full inventory to Logger under logTag (default "MAPVIEW_REPORT").
    // Safe to call from the shutdown path (Logger must still be live).
    void Report(const char* logTag = "MAPVIEW_REPORT");

private:
    MapViewTypeTracker();
    ~MapViewTypeTracker();

    // ── Aggregate view counters ───────────────────────────────────────────────
    volatile LONG64 m_cntAnonymous       = 0;
    volatile LONG64 m_cntImage           = 0;
    volatile LONG64 m_cntOtherFile       = 0;
    volatile LONG64 m_cntNoName          = 0;
    volatile LONG64 m_cntPkgNoDbpf       = 0;
    volatile LONG64 m_cntPkgDbpf         = 0;

    volatile LONG64 m_bytesAnonymous     = 0;
    volatile LONG64 m_bytesImage         = 0;
    volatile LONG64 m_bytesOtherFile     = 0;
    volatile LONG64 m_bytesNoName        = 0;
    volatile LONG64 m_bytesPkgNoDbpf     = 0;
    volatile LONG64 m_bytesPkgDbpf       = 0;

    volatile LONG64 m_cntRedirected      = 0;
    volatile LONG64 m_bytesRedirected    = 0;

    // ── Per-type DBPF table ───────────────────────────────────────────────────
    // Fixed-size open-addressing table keyed by typeId.
    // Capacity 256 gives load-factor ≤ 0.5 for the ~40 known TS3 DBPF types.
    static const int kTypeTableCap = 256;
    struct TypeSlot {
        uint32_t         typeId;        // 0 == empty
        volatile LONG64  entryCount;    // sum of DbpfTypeStats.entryCount
        volatile LONG64  totalBytes;    // sum of DbpfTypeStats.totalMemBytes
        volatile LONG64  viewCount;     // number of views containing this typeId
    };
    TypeSlot m_typeTable[kTypeTableCap];

    // ── Per-filename table ────────────────────────────────────────────────────
    // Tracks top-N distinct base names (case-insensitive) seen in any view.
    static const int kMaxFiles = 64;
    struct FileSlot {
        char             name[80];      // truncated base name
        volatile LONG64  viewCount;
        volatile LONG64  totalBytes;
    };
    FileSlot m_files[kMaxFiles];
    int      m_fileCount = 0;          // guarded by m_cs for insertion only

    // ── Type-ID redirect allow-list ───────────────────────────────────────────
    static const int kMaxAllowIds = 64;
    uint32_t m_allowIds[kMaxAllowIds];
    int      m_allowCount = 0;

    CRITICAL_SECTION m_cs;
    bool             m_csInit = false;

    // ── Internal helpers ──────────────────────────────────────────────────────
    TypeSlot* FindOrInsertType(uint32_t typeId);   // returns nullptr on table full
    void      RecordFileName(const char* baseName, uint64_t bytes);

    static MapViewTypeTracker* s_instance;
};
