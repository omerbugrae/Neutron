// COM server entry points: DllMain, DllGetClassObject, DllCanUnloadNow,
// DllRegisterServer, DllUnregisterServer. Registration writes machine-wide
// keys under HKEY_LOCAL_MACHINE (not HKEY_CLASSES_ROOT) so that it applies
// regardless of which user account the scanned host process runs as; this
// requires the caller to already be elevated (see tools/amsi/register.ps1).
#include "NeutronAmsi.h"
#include "ClassFactory.h"
#include <olectl.h>
#include <cstdio>

HMODULE g_hModule = nullptr;

BOOL APIENTRY DllMain(HMODULE module, DWORD reason, LPVOID) {
    if (reason == DLL_PROCESS_ATTACH) {
        g_hModule = module;
        DisableThreadLibraryCalls(module);
    }
    return TRUE;
}

STDAPI DllGetClassObject(REFCLSID rclsid, REFIID riid, void** ppv) {
    if (!ppv) return E_POINTER;
    *ppv = nullptr;
    if (rclsid != CLSID_NeutronAmsiProvider) return CLASS_E_CLASSNOTAVAILABLE;

    CNeutronClassFactory* factory = new (std::nothrow) CNeutronClassFactory();
    if (!factory) return E_OUTOFMEMORY;
    HRESULT hr = factory->QueryInterface(riid, ppv);
    factory->Release();
    return hr;
}

STDAPI DllCanUnloadNow() { return NeutronAmsi_ModuleRefCount() == 0 ? S_OK : S_FALSE; }

namespace {

LSTATUS SetStringValue(HKEY key, const wchar_t* name, const std::wstring& value) {
    return RegSetValueExW(key, name, 0, REG_SZ, reinterpret_cast<const BYTE*>(value.c_str()),
                           static_cast<DWORD>((value.size() + 1) * sizeof(wchar_t)));
}

}  // namespace

STDAPI DllRegisterServer() {
    std::wstring clsidText = NeutronAmsi_ClsidToString(CLSID_NeutronAmsiProvider);
    std::wstring modulePath = NeutronAmsi_ModulePath();
    if (modulePath.empty()) return SELFREG_E_CLASS;

    wchar_t clsidKeyPath[256];
    swprintf_s(clsidKeyPath, kClsidKeyFormat, clsidText.c_str());

    HKEY clsidKey = nullptr;
    LSTATUS status = RegCreateKeyExW(HKEY_LOCAL_MACHINE, clsidKeyPath, 0, nullptr, 0,
                                      KEY_WRITE, nullptr, &clsidKey, nullptr);
    if (status != ERROR_SUCCESS) return SELFREG_E_CLASS;
    SetStringValue(clsidKey, nullptr, L"Neutron AMSI Provider");

    HKEY inprocKey = nullptr;
    status = RegCreateKeyExW(clsidKey, L"InprocServer32", 0, nullptr, 0, KEY_WRITE, nullptr,
                              &inprocKey, nullptr);
    if (status == ERROR_SUCCESS) {
        SetStringValue(inprocKey, nullptr, modulePath);
        SetStringValue(inprocKey, L"ThreadingModel", L"Both");
        RegCloseKey(inprocKey);
    }
    RegCloseKey(clsidKey);

    wchar_t providerKeyPath[256];
    swprintf_s(providerKeyPath, kProviderKeyFormat, clsidText.c_str());
    HKEY providerKey = nullptr;
    status = RegCreateKeyExW(HKEY_LOCAL_MACHINE, providerKeyPath, 0, nullptr, 0, KEY_WRITE,
                              nullptr, &providerKey, nullptr);
    if (status != ERROR_SUCCESS) return SELFREG_E_CLASS;
    SetStringValue(providerKey, nullptr, L"Neutron Security");
    RegCloseKey(providerKey);

    return S_OK;
}

STDAPI DllUnregisterServer() {
    std::wstring clsidText = NeutronAmsi_ClsidToString(CLSID_NeutronAmsiProvider);

    wchar_t providerKeyPath[256];
    swprintf_s(providerKeyPath, kProviderKeyFormat, clsidText.c_str());
    RegDeleteKeyW(HKEY_LOCAL_MACHINE, providerKeyPath);

    wchar_t clsidKeyPath[256];
    swprintf_s(clsidKeyPath, kClsidKeyFormat, clsidText.c_str());
    wchar_t inprocKeyPath[300];
    swprintf_s(inprocKeyPath, L"%s\\InprocServer32", clsidKeyPath);
    RegDeleteKeyW(HKEY_LOCAL_MACHINE, inprocKeyPath);
    RegDeleteKeyW(HKEY_LOCAL_MACHINE, clsidKeyPath);

    return S_OK;
}
