// Minimal named-pipe client used to hand an AMSI scan buffer to the Neutron
// engine's --amsi-service process for deep (YARA/signature) analysis.
//
// Wire protocol (deliberately not JSON -- avoids pulling a JSON library into
// the COM server): a single request line and a single response line, fields
// separated by the ASCII unit separator (0x1F), terminated by '\n'.
//
//   request:  SCAN\x1F<content_name>\x1F<app_name>\x1F<base64 buffer>\n
//   response: VERDICT\x1F<clean|detected>\x1F<reason>\n
//
// The whole round trip (connect + write + read) is bounded by
// kPipeBudgetMillis. Any failure or timeout is treated by the caller as
// "fail open" (AMSI_RESULT_NOT_DETECTED) so a stopped/missing Neutron
// service never blocks the host application's scripts.
#pragma once

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <string>

namespace neutron_amsi {

constexpr DWORD kPipeBudgetMillis = 150;

struct PipeVerdict {
    bool reached = false;   // true if the service responded at all
    bool detected = false;  // true if the service flagged the content
    std::string reason;
};

// Performs the full request/response exchange within kPipeBudgetMillis.
// Never throws; on any error PipeVerdict::reached stays false.
PipeVerdict ScanViaPipe(const std::wstring& contentName,
                         const std::wstring& appName,
                         const unsigned char* data,
                         size_t size);

std::string Base64Encode(const unsigned char* data, size_t size);

}  // namespace neutron_amsi
