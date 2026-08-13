// Shared declarations for the Neutron AMSI provider COM server.
#pragma once

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <amsi.h>
#include <string>
#include <vector>
#include <cstdint>

// {ADACFA90-B877-414D-A818-2EA5291E290E}
extern const CLSID CLSID_NeutronAmsiProvider;

// Registry paths (relative to HKEY_LOCAL_MACHINE) used at registration time.
extern const wchar_t* const kClsidKeyFormat;    // SOFTWARE\Classes\CLSID\{guid}
extern const wchar_t* const kProviderKeyFormat; // SOFTWARE\Microsoft\AMSI\Providers\{guid}

extern const wchar_t* const kPipeName; // \\.\pipe\neutron-amsi

// Module-wide reference counting for DllCanUnloadNow.
LONG NeutronAmsi_AddModuleRef();
LONG NeutronAmsi_ReleaseModuleRef();
LONG NeutronAmsi_ModuleRefCount();

std::wstring NeutronAmsi_ClsidToString(const CLSID& clsid);
std::wstring NeutronAmsi_ModulePath();
