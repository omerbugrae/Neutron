#include "PipeClient.h"
#include "NeutronAmsi.h"
#include <cstdio>

namespace neutron_amsi {

namespace {

constexpr char kFieldSeparator = '\x1F';

// Encodes UTF-16 to UTF-8 for the wire; the pipe protocol is byte-oriented.
std::string Utf16ToUtf8(const std::wstring& value) {
    if (value.empty()) return {};
    int needed = WideCharToMultiByte(CP_UTF8, 0, value.c_str(), (int)value.size(), nullptr, 0,
                                      nullptr, nullptr);
    if (needed <= 0) return {};
    std::string out(needed, '\0');
    WideCharToMultiByte(CP_UTF8, 0, value.c_str(), (int)value.size(), out.data(), needed, nullptr,
                         nullptr);
    return out;
}

// Remaining budget helper: never returns a negative/zero value the caller
// could misread as "no timeout" -- callers must check for <= 0 explicitly.
DWORD RemainingMillis(ULONGLONG deadline) {
    ULONGLONG now = GetTickCount64();
    if (now >= deadline) return 0;
    return static_cast<DWORD>(deadline - now);
}

}  // namespace

std::string Base64Encode(const unsigned char* data, size_t size) {
    static const char table[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string out;
    out.reserve(((size + 2) / 3) * 4);
    size_t i = 0;
    while (i + 3 <= size) {
        uint32_t chunk = (data[i] << 16) | (data[i + 1] << 8) | data[i + 2];
        out.push_back(table[(chunk >> 18) & 0x3F]);
        out.push_back(table[(chunk >> 12) & 0x3F]);
        out.push_back(table[(chunk >> 6) & 0x3F]);
        out.push_back(table[chunk & 0x3F]);
        i += 3;
    }
    size_t remaining = size - i;
    if (remaining == 1) {
        uint32_t chunk = data[i] << 16;
        out.push_back(table[(chunk >> 18) & 0x3F]);
        out.push_back(table[(chunk >> 12) & 0x3F]);
        out.push_back('=');
        out.push_back('=');
    } else if (remaining == 2) {
        uint32_t chunk = (data[i] << 16) | (data[i + 1] << 8);
        out.push_back(table[(chunk >> 18) & 0x3F]);
        out.push_back(table[(chunk >> 12) & 0x3F]);
        out.push_back(table[(chunk >> 6) & 0x3F]);
        out.push_back('=');
    }
    return out;
}

PipeVerdict ScanViaPipe(const std::wstring& contentName, const std::wstring& appName,
                         const unsigned char* data, size_t size) {
    PipeVerdict verdict;
    ULONGLONG deadline = GetTickCount64() + kPipeBudgetMillis;

    // Non-blocking-ish connect: wait briefly if every instance is busy,
    // rather than failing immediately (the engine may be mid-request).
    HANDLE pipe = CreateFileW(kPipeName, GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_EXISTING,
                               FILE_FLAG_OVERLAPPED, nullptr);
    if (pipe == INVALID_HANDLE_VALUE) {
        if (GetLastError() != ERROR_PIPE_BUSY) return verdict;
        DWORD remaining = RemainingMillis(deadline);
        if (remaining == 0 || !WaitNamedPipeW(kPipeName, remaining)) return verdict;
        pipe = CreateFileW(kPipeName, GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_EXISTING,
                            FILE_FLAG_OVERLAPPED, nullptr);
        if (pipe == INVALID_HANDLE_VALUE) return verdict;
    }

    DWORD mode = PIPE_READMODE_BYTE;
    SetNamedPipeHandleState(pipe, &mode, nullptr, nullptr);

    HANDLE event = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    if (!event) {
        CloseHandle(pipe);
        return verdict;
    }

    std::string request;
    request.reserve(size * 4 / 3 + 256);
    request += "SCAN";
    request += kFieldSeparator;
    request += Utf16ToUtf8(contentName);
    request += kFieldSeparator;
    request += Utf16ToUtf8(appName);
    request += kFieldSeparator;
    request += Base64Encode(data, size);
    request += '\n';

    OVERLAPPED overlapped = {};
    overlapped.hEvent = event;
    DWORD written = 0;
    BOOL ok = WriteFile(pipe, request.data(), (DWORD)request.size(), nullptr, &overlapped);
    if (!ok && GetLastError() != ERROR_IO_PENDING) {
        CloseHandle(event);
        CloseHandle(pipe);
        return verdict;
    }
    DWORD writeWait = RemainingMillis(deadline);
    if (writeWait == 0 ||
        WaitForSingleObject(event, writeWait) != WAIT_OBJECT_0 ||
        !GetOverlappedResult(pipe, &overlapped, &written, FALSE)) {
        CancelIoEx(pipe, &overlapped);
        CloseHandle(event);
        CloseHandle(pipe);
        return verdict;
    }

    char responseBuffer[4096] = {};
    ResetEvent(event);
    OVERLAPPED readOverlapped = {};
    readOverlapped.hEvent = event;
    DWORD readBytes = 0;
    ok = ReadFile(pipe, responseBuffer, sizeof(responseBuffer) - 1, nullptr, &readOverlapped);
    if (!ok && GetLastError() != ERROR_IO_PENDING) {
        CloseHandle(event);
        CloseHandle(pipe);
        return verdict;
    }
    DWORD readWait = RemainingMillis(deadline);
    if (readWait == 0 ||
        WaitForSingleObject(event, readWait) != WAIT_OBJECT_0 ||
        !GetOverlappedResult(pipe, &readOverlapped, &readBytes, FALSE)) {
        CancelIoEx(pipe, &readOverlapped);
        CloseHandle(event);
        CloseHandle(pipe);
        return verdict;
    }

    CloseHandle(event);
    CloseHandle(pipe);

    std::string response(responseBuffer, readBytes);
    // VERDICT\x1F<clean|detected>\x1F<reason>\n
    size_t firstSep = response.find(kFieldSeparator);
    if (firstSep == std::string::npos || response.compare(0, firstSep, "VERDICT") != 0) {
        return verdict;
    }
    size_t secondSep = response.find(kFieldSeparator, firstSep + 1);
    if (secondSep == std::string::npos) return verdict;
    std::string status = response.substr(firstSep + 1, secondSep - firstSep - 1);
    std::string reason = response.substr(secondSep + 1);
    while (!reason.empty() && (reason.back() == '\n' || reason.back() == '\r')) reason.pop_back();

    verdict.reached = true;
    verdict.detected = (status == "detected");
    verdict.reason = reason;
    return verdict;
}

}  // namespace neutron_amsi
