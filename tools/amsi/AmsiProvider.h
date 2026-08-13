// IAntimalwareProvider implementation. Fast local checks run in-process;
// anything inconclusive is forwarded to the Neutron engine over a named
// pipe with a strict timeout (see PipeClient.h). On any doubt this provider
// fails open: a missing/slow Neutron service must never block scripts that
// Windows itself (or unrelated software) depends on.
#pragma once

#include "NeutronAmsi.h"

class CNeutronAmsiProvider : public IAntimalwareProvider {
public:
    CNeutronAmsiProvider();

    // IUnknown
    HRESULT STDMETHODCALLTYPE QueryInterface(REFIID riid, void** ppvObject) override;
    ULONG STDMETHODCALLTYPE AddRef() override;
    ULONG STDMETHODCALLTYPE Release() override;

    // IAntimalwareProvider
    HRESULT STDMETHODCALLTYPE Scan(IAmsiStream* stream, AMSI_RESULT* result) override;
    void STDMETHODCALLTYPE CloseSession(ULONGLONG session) override;
    HRESULT STDMETHODCALLTYPE DisplayName(LPWSTR* displayName) override;

private:
    LONG refCount_;
};
