#include "AmsiProvider.h"
#include "PipeClient.h"
#include <cstring>

namespace {

// Caps how much of a stream we pull into memory/off to the pipe. Scripts
// and macros AMSI hands us are almost always well under this; a huge
// buffer is itself unusual and we fail open on it rather than stalling.
constexpr ULONGLONG kMaxBufferBytes = 8ULL * 1024 * 1024;

// Microsoft's published AMSI conformance test string. Any provider that
// does not flag this exact string is considered non-functional by tools
// like Test-AmsiProvider, so this check must never go through the pipe.
const char kAmsiTestStringUtf8[] = "AMSI Test Sample: 7e72c3ce-861b-4339-8740-0ac1484c1386";

bool ContainsAscii(const unsigned char* data, size_t size, const char* needle) {
    size_t needleLen = strlen(needle);
    if (needleLen == 0 || size < needleLen) return false;
    for (size_t i = 0; i + needleLen <= size; ++i) {
        if (memcmp(data + i, needle, needleLen) == 0) return true;
    }
    return false;
}

// Same literal, but as it would appear if the host handed us UTF-16LE text
// (common for PowerShell script blocks) -- every ASCII byte followed by a
// zero byte.
bool ContainsUtf16(const unsigned char* data, size_t size, const char* needleAscii) {
    size_t needleLen = strlen(needleAscii);
    size_t wideLen = needleLen * 2;
    if (size < wideLen) return false;
    for (size_t i = 0; i + wideLen <= size; ++i) {
        bool match = true;
        for (size_t j = 0; j < needleLen; ++j) {
            if (data[i + j * 2] != (unsigned char)needleAscii[j] || data[i + j * 2 + 1] != 0) {
                match = false;
                break;
            }
        }
        if (match) return true;
    }
    return false;
}

ULONGLONG ClampU64(ULONGLONG value, ULONGLONG maxValue) {
    return value > maxValue ? maxValue : value;
}

bool ReadStreamBuffer(IAmsiStream* stream, std::vector<unsigned char>& out) {
    ULONGLONG size = 0;
    ULONG retData = 0;
    HRESULT hr = stream->GetAttribute(AMSI_ATTRIBUTE_CONTENT_SIZE, sizeof(size),
                                       reinterpret_cast<unsigned char*>(&size), &retData);
    if (FAILED(hr) || size == 0) return false;
    size = ClampU64(size, kMaxBufferBytes);

    out.resize(static_cast<size_t>(size));
    ULONGLONG offset = 0;
    while (offset < size) {
        ULONG chunk = static_cast<ULONG>(ClampU64(size - offset, 64 * 1024));
        ULONG readSize = 0;
        HRESULT readHr = stream->Read(offset, chunk, out.data() + offset, &readSize);
        if (FAILED(readHr) || readSize == 0) break;
        // The host owns this implementation; a readSize larger than the
        // chunk we asked for would walk the next iteration's write past the
        // end of `out` and corrupt the heap of whatever process AMSI loaded
        // us into. Never trust it further than the request.
        if (readSize > chunk) {
            offset += chunk;
            break;
        }
        offset += readSize;
    }
    out.resize(static_cast<size_t>(offset));
    return !out.empty();
}

// Reads a string attribute (app/content name) into a fixed local buffer.
// AMSI names are short (paths/identifiers); anything not fitting is
// truncated rather than causing a second allocating round trip.
std::wstring ReadStreamName(IAmsiStream* stream, AMSI_ATTRIBUTE attribute) {
    // A wchar_t-typed buffer (rather than unsigned char cast to wchar_t*)
    // guarantees the 2-byte alignment GetAttribute's UTF-16 output needs.
    wchar_t buffer[512] = {};
    ULONG retData = 0;
    HRESULT hr = stream->GetAttribute(attribute, sizeof(buffer),
                                       reinterpret_cast<unsigned char*>(buffer), &retData);
    if (FAILED(hr) || retData == 0) return L"";
    // retData is the host's claim about how much it wrote; clamp it to what
    // the buffer can actually hold before it is used as a length.
    if (retData > sizeof(buffer)) retData = sizeof(buffer);
    size_t charCount = retData / sizeof(wchar_t);
    while (charCount > 0 && buffer[charCount - 1] == L'\0') --charCount;
    return std::wstring(buffer, charCount);
}

bool LocalFastVerdictIsDetection(const unsigned char* data, size_t size) {
    return ContainsAscii(data, size, kAmsiTestStringUtf8) ||
           ContainsUtf16(data, size, kAmsiTestStringUtf8);
}

// The real scanning logic, kept in its own function so the SEH __try/
// __except wrapper below (which cannot share a frame with C++ objects that
// need unwinding, e.g. the std::vector/std::wstring used here) stays a
// thin, object-free shell. __declspec(noinline) is load-bearing: at /O2 the
// optimizer would otherwise pull this body into Scan's __try frame, where a
// caught SEH exception skips the C++ destructors entirely.
__declspec(noinline) void ScanInternal(IAmsiStream* stream, AMSI_RESULT* result) {
    std::vector<unsigned char> buffer;
    if (!ReadStreamBuffer(stream, buffer)) return;  // nothing to scan -> fail open

    if (LocalFastVerdictIsDetection(buffer.data(), buffer.size())) {
        *result = AMSI_RESULT_DETECTED;
        return;
    }

    std::wstring contentName = ReadStreamName(stream, AMSI_ATTRIBUTE_CONTENT_NAME);
    std::wstring appName = ReadStreamName(stream, AMSI_ATTRIBUTE_APP_NAME);

    auto verdict = neutron_amsi::ScanViaPipe(contentName, appName, buffer.data(), buffer.size());
    // Not reached (service down, timeout, pipe busy past budget): fail
    // open. A missing Neutron service must never block the host script.
    if (verdict.reached && verdict.detected) {
        *result = AMSI_RESULT_DETECTED;
    }
}

}  // namespace

// Starts at one reference, held on behalf of the caller that is about to
// receive this pointer. With a zero start, CreateInstance's QueryInterface/
// Release pair took the count 0 -> 1 -> 0 and deleted the provider before
// returning it, leaving AMSI to call Scan on freed memory -- a use-after-free
// that corrupts the heap of every host that loads us (PowerShell dying with
// STATUS_HEAP_CORRUPTION / 0xC0000374 during setup).
CNeutronAmsiProvider::CNeutronAmsiProvider() : refCount_(1) { NeutronAmsi_AddModuleRef(); }

HRESULT STDMETHODCALLTYPE CNeutronAmsiProvider::QueryInterface(REFIID riid, void** ppvObject) {
    if (!ppvObject) return E_POINTER;
    if (riid == IID_IUnknown || riid == IID_IAntimalwareProvider) {
        *ppvObject = static_cast<IAntimalwareProvider*>(this);
        AddRef();
        return S_OK;
    }
    *ppvObject = nullptr;
    return E_NOINTERFACE;
}

ULONG STDMETHODCALLTYPE CNeutronAmsiProvider::AddRef() {
    return InterlockedIncrement(&refCount_);
}

ULONG STDMETHODCALLTYPE CNeutronAmsiProvider::Release() {
    LONG count = InterlockedDecrement(&refCount_);
    if (count == 0) {
        NeutronAmsi_ReleaseModuleRef();
        delete this;
    }
    return count;
}

HRESULT STDMETHODCALLTYPE CNeutronAmsiProvider::Scan(IAmsiStream* stream, AMSI_RESULT* result) {
    if (!stream || !result) return E_POINTER;
    *result = AMSI_RESULT_NOT_DETECTED;

    // This provider is loaded in-process by every application that calls
    // AMSI (PowerShell, wscript, Office, ...). A bug here must never be
    // able to crash or hang the host: any fault -- null deref, out-of-
    // bounds access, whatever -- is caught and treated as "not detected"
    // rather than propagating. (Windows heap-corruption fail-fast and
    // stack overflow are the one class of fault SEH structurally cannot
    // intercept; the bounded, pre-sized buffers in ReadStreamBuffer/
    // ReadStreamName exist specifically to avoid ever triggering that.)
    __try {
        ScanInternal(stream, result);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        *result = AMSI_RESULT_NOT_DETECTED;
    }
    return S_OK;
}

void STDMETHODCALLTYPE CNeutronAmsiProvider::CloseSession(ULONGLONG /*session*/) {
    // Stateless provider: nothing tracked per-session.
}

HRESULT STDMETHODCALLTYPE CNeutronAmsiProvider::DisplayName(LPWSTR* displayName) {
    if (!displayName) return E_POINTER;
    static const wchar_t kName[] = L"Neutron Security";
    size_t bytes = sizeof(kName);
    *displayName = static_cast<LPWSTR>(CoTaskMemAlloc(bytes));
    if (!*displayName) return E_OUTOFMEMORY;
    memcpy(*displayName, kName, bytes);
    return S_OK;
}
