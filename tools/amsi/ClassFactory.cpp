#include "ClassFactory.h"
#include "AmsiProvider.h"

CNeutronClassFactory::CNeutronClassFactory() : refCount_(0) { NeutronAmsi_AddModuleRef(); }

HRESULT STDMETHODCALLTYPE CNeutronClassFactory::QueryInterface(REFIID riid, void** ppvObject) {
    if (!ppvObject) return E_POINTER;
    if (riid == IID_IUnknown || riid == IID_IClassFactory) {
        *ppvObject = static_cast<IClassFactory*>(this);
        AddRef();
        return S_OK;
    }
    *ppvObject = nullptr;
    return E_NOINTERFACE;
}

ULONG STDMETHODCALLTYPE CNeutronClassFactory::AddRef() { return InterlockedIncrement(&refCount_); }

ULONG STDMETHODCALLTYPE CNeutronClassFactory::Release() {
    LONG count = InterlockedDecrement(&refCount_);
    if (count == 0) {
        NeutronAmsi_ReleaseModuleRef();
        delete this;
    }
    return count;
}

HRESULT STDMETHODCALLTYPE CNeutronClassFactory::CreateInstance(IUnknown* outer, REFIID riid,
                                                                 void** ppvObject) {
    if (!ppvObject) return E_POINTER;
    *ppvObject = nullptr;
    if (outer) return CLASS_E_NOAGGREGATION;

    CNeutronAmsiProvider* provider = new (std::nothrow) CNeutronAmsiProvider();
    if (!provider) return E_OUTOFMEMORY;

    HRESULT hr = provider->QueryInterface(riid, ppvObject);
    provider->Release();
    return hr;
}

HRESULT STDMETHODCALLTYPE CNeutronClassFactory::LockServer(BOOL lock) {
    if (lock) {
        NeutronAmsi_AddModuleRef();
    } else {
        NeutronAmsi_ReleaseModuleRef();
    }
    return S_OK;
}
