#include "NeutronAmsi.h"
#include <initguid.h>
#include <cstdio>

// amsi.h only forward-declares IID_IAntimalwareProvider (EXTERN_C const IID);
// the Windows SDK ships no amsi_i.c to provide the storage, and amsi.lib
// only exports the client-side Amsi* functions -- so we define it here
// ourselves from the same UUID string amsi.h uses in its MIDL_INTERFACE
// attribute for IAntimalwareProvider ("b2cabfe3-fe04-42b1-a5df-08d483d4d125").
DEFINE_GUID(IID_IAntimalwareProvider, 0xb2cabfe3, 0xfe04, 0x42b1, 0xa5, 0xdf, 0x08, 0xd4, 0x83,
            0xd4, 0xd1, 0x25);

// {ADACFA90-B877-414D-A818-2EA5291E290E}
const CLSID CLSID_NeutronAmsiProvider = {
    0xadacfa90, 0xb877, 0x414d, {0xa8, 0x18, 0x2e, 0xa5, 0x29, 0x1e, 0x29, 0x0e}};

const wchar_t* const kClsidKeyFormat = L"SOFTWARE\\Classes\\CLSID\\%s";
const wchar_t* const kProviderKeyFormat = L"SOFTWARE\\Microsoft\\AMSI\\Providers\\%s";
const wchar_t* const kPipeName = L"\\\\.\\pipe\\neutron-amsi";

static LONG g_moduleRefCount = 0;

LONG NeutronAmsi_AddModuleRef() { return InterlockedIncrement(&g_moduleRefCount); }
LONG NeutronAmsi_ReleaseModuleRef() { return InterlockedDecrement(&g_moduleRefCount); }
LONG NeutronAmsi_ModuleRefCount() { return g_moduleRefCount; }

std::wstring NeutronAmsi_ClsidToString(const CLSID& clsid) {
    wchar_t buffer[64] = {};
    // {XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX}
    swprintf_s(buffer, L"{%08lX-%04hX-%04hX-%02hhX%02hhX-%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX}",
               clsid.Data1, clsid.Data2, clsid.Data3, clsid.Data4[0], clsid.Data4[1],
               clsid.Data4[2], clsid.Data4[3], clsid.Data4[4], clsid.Data4[5], clsid.Data4[6],
               clsid.Data4[7]);
    return buffer;
}

extern HMODULE g_hModule; // defined in Dll.cpp

std::wstring NeutronAmsi_ModulePath() {
    wchar_t path[MAX_PATH] = {};
    GetModuleFileNameW(g_hModule, path, MAX_PATH);
    return path;
}
