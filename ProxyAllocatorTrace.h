#pragma once
#include <windows.h>

struct ProxyAllocatorTrace {
    struct TraceRec {
        LARGE_INTEGER qpc;
        DWORD tid;
        DWORD code;
        DWORD spanId;
        ULONGLONG seq;
        HANDLE h;
        SIZE_T a;
        SIZE_T b;
        DWORD err;
        BYTE  ctx;
        BYTE  depth;
        BYTE  reserved[6];
        void* rip;
    };

    static void Initialize();
    static void Emit(DWORD code, DWORD spanId, HANDLE h, SIZE_T a, SIZE_T b, DWORD err, BYTE ctx, BYTE depth, void* rip);
    static void Mark(DWORD code, HANDLE h, SIZE_T a, SIZE_T b, DWORD err, BYTE ctx);
    static DWORD SpanBegin(DWORD code, HANDLE h, SIZE_T a, SIZE_T b, BYTE ctx);
    static void SpanEnd(DWORD spanId, DWORD code, HANDLE h, SIZE_T a, SIZE_T b, DWORD err, BYTE ctx);
    static SIZE_T CopySnapshot(void* dst, SIZE_T bytes);

    static volatile LONG      s_traceWriteIdx;
    static volatile ULONGLONG s_traceSeq;
    static TraceRec*          s_traceBuf;
    static SIZE_T             s_traceCap;
    static LARGE_INTEGER      s_qpcFreq;
    static volatile LONG      s_spanIdGen;
};