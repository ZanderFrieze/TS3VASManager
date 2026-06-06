#include "ProxyAllocatorTrace.h"
#include <intrin.h>

static const SIZE_T kTraceCapacity = 8192;

volatile LONG      ProxyAllocatorTrace::s_traceWriteIdx = -1;
volatile ULONGLONG ProxyAllocatorTrace::s_traceSeq      =  0;
ProxyAllocatorTrace::TraceRec* ProxyAllocatorTrace::s_traceBuf = nullptr;
SIZE_T             ProxyAllocatorTrace::s_traceCap = 0;
LARGE_INTEGER      ProxyAllocatorTrace::s_qpcFreq = {};
volatile LONG      ProxyAllocatorTrace::s_spanIdGen = 1;

extern DWORD ProxyAllocator_GetTlsDepth();
extern BYTE ProxyAllocator_GetContextTag();

void ProxyAllocatorTrace::Initialize() {
    if (s_traceBuf) return;
    s_traceCap = kTraceCapacity;
    s_traceBuf = (TraceRec*)VirtualAlloc(nullptr, s_traceCap * sizeof(TraceRec), MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    if (!s_traceBuf) return;
    QueryPerformanceFrequency(&s_qpcFreq);
    LARGE_INTEGER now; QueryPerformanceCounter(&now);
    s_traceWriteIdx = -1;
    s_traceSeq = 0;
    for (SIZE_T i = 0; i < s_traceCap; ++i) {
        s_traceBuf[i].qpc = now;
        s_traceBuf[i].tid = 0;
        s_traceBuf[i].code = 0;
        s_traceBuf[i].spanId = 0;
        s_traceBuf[i].seq = 0;
        s_traceBuf[i].h = nullptr;
        s_traceBuf[i].a = 0;
        s_traceBuf[i].b = 0;
        s_traceBuf[i].err = 0;
        s_traceBuf[i].ctx = 0;
        s_traceBuf[i].depth = 0;
        s_traceBuf[i].rip = nullptr;
    }
}

void ProxyAllocatorTrace::Emit(DWORD code, DWORD spanId, HANDLE h, SIZE_T a, SIZE_T b, DWORD err, BYTE ctx, BYTE depth, void* rip) {
    if (!s_traceBuf) return;
    LONG idx = InterlockedIncrement(&s_traceWriteIdx);
    SIZE_T slot = ((SIZE_T)idx) % s_traceCap;
    TraceRec* r = &s_traceBuf[slot];
    QueryPerformanceCounter(&r->qpc);
    r->tid  = GetCurrentThreadId();
    r->code = code;
    r->spanId = spanId;
    r->seq = InterlockedIncrement64((volatile LONG64*)&s_traceSeq);
    r->h    = h;
    r->a    = a;
    r->b    = b;
    r->err  = err;
    r->ctx  = ctx;
    r->depth = depth;
    r->rip  = rip;
}

void ProxyAllocatorTrace::Mark(DWORD code, HANDLE h, SIZE_T a, SIZE_T b, DWORD err, BYTE ctx) {
    BYTE depth = (BYTE)ProxyAllocator_GetTlsDepth();
    Emit(code, 0, h, a, b, err, ctx, depth, _ReturnAddress());
}

DWORD ProxyAllocatorTrace::SpanBegin(DWORD code, HANDLE h, SIZE_T a, SIZE_T b, BYTE ctx) {
    DWORD id = (DWORD)InterlockedIncrement(&s_spanIdGen);
    BYTE depth = (BYTE)(ProxyAllocator_GetTlsDepth());
    Emit(code, id, h, a, b, 0, ctx, (BYTE)(depth + 1), _ReturnAddress());
    return id;
}

void ProxyAllocatorTrace::SpanEnd(DWORD spanId, DWORD code, HANDLE h, SIZE_T a, SIZE_T b, DWORD err, BYTE ctx) {
    BYTE depth = (BYTE)ProxyAllocator_GetTlsDepth();
    Emit(code, spanId, h, a, b, err, ctx, depth, _ReturnAddress());
}

SIZE_T ProxyAllocatorTrace::CopySnapshot(void* dst, SIZE_T bytes) {
    if (!dst || !s_traceBuf) return 0;
    SIZE_T want = s_traceCap * sizeof(TraceRec);
    SIZE_T n = (bytes < want) ? bytes : want;
    volatile char* src = (volatile char*)s_traceBuf;
    char* d = (char*)dst;
    for (SIZE_T i = 0; i < n; ++i) d[i] = src[i];
    return n;
}