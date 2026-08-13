// Minimal Windows Service Control Manager (SCM) shim. Its only job is to
// speak the SCM protocol and supervise neutron-engine.exe --service-host
// as a child process, restarting it if it exits unexpectedly. All real
// protection logic lives in the Python engine; this file stays deliberately
// tiny (SCM plumbing only) so the bulk of the codebase can stay in
// Python/JS, matching this project's established "small native component
// only where the OS forces it" pattern (see tools/amsi/).
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <string>

namespace {

const wchar_t* const kServiceName = L"NeutronService";
SERVICE_STATUS g_status = {};
SERVICE_STATUS_HANDLE g_statusHandle = nullptr;
HANDLE g_stopEvent = nullptr;
PROCESS_INFORMATION g_childProcess = {};

// Resolves neutron-engine.exe relative to this executable's own path
// (runtime\service\x64\NeutronServiceHost.exe -> runtime\engine\x64\...),
// so the service works whether installed to Program Files or run from a
// dev build output directory -- no registry/env lookup needed.
std::wstring EnginePath() {
    wchar_t modulePath[MAX_PATH] = {};
    GetModuleFileNameW(nullptr, modulePath, MAX_PATH);
    std::wstring path(modulePath);
    size_t lastSlash = path.find_last_of(L"\\/");
    if (lastSlash == std::wstring::npos) return L"";
    std::wstring dir = path.substr(0, lastSlash);
    return dir + L"\\..\\..\\engine\\x64\\neutron-engine\\neutron-engine.exe";
}

void ReportStatus(DWORD state, DWORD exitCode = NO_ERROR, DWORD waitHint = 0) {
    static DWORD checkpoint = 1;
    g_status.dwCurrentState = state;
    g_status.dwWin32ExitCode = exitCode;
    g_status.dwWaitHint = waitHint;
    g_status.dwCheckPoint = (state == SERVICE_RUNNING || state == SERVICE_STOPPED) ? 0 : checkpoint++;
    SetServiceStatus(g_statusHandle, &g_status);
}

// Neutron.exe/main.cjs already resolves NEUTRON_DATA_DIR per-user
// (%APPDATA%\Neutron\data) for the old spawn-a-subprocess-as-the-user
// model. Running as LocalSystem has no meaningful "current user" profile,
// so the service sets a machine-wide %ProgramData%\Neutron\data instead,
// via the current (service) process's own environment -- CreateProcessW
// with lpEnvironment=nullptr below inherits it into the child.
void ConfigureServiceEnvironment() {
    wchar_t programData[MAX_PATH] = {};
    DWORD length = GetEnvironmentVariableW(L"ProgramData", programData, MAX_PATH);
    std::wstring dataDir = (length > 0 && length < MAX_PATH)
        ? std::wstring(programData) + L"\\Neutron\\data"
        : L"C:\\ProgramData\\Neutron\\data";
    SetEnvironmentVariableW(L"NEUTRON_DATA_DIR", dataDir.c_str());

    // Best-effort: the read-only bundled signature/rule base ships next to
    // this executable's own install tree (three levels up from
    // runtime\service\x64\ to the app root, then into data\). Unverified
    // against a real packaged install -- flagged as a follow-up check.
    wchar_t modulePath[MAX_PATH] = {};
    GetModuleFileNameW(nullptr, modulePath, MAX_PATH);
    std::wstring path(modulePath);
    size_t lastSlash = path.find_last_of(L"\\/");
    if (lastSlash != std::wstring::npos) {
        std::wstring bundledDataDir = path.substr(0, lastSlash) + L"\\..\\..\\..\\data";
        SetEnvironmentVariableW(L"NEUTRON_BUNDLED_DATA_DIR", bundledDataDir.c_str());
    }
}

bool LaunchEngine() {
    std::wstring enginePath = EnginePath();
    if (enginePath.empty()) return false;

    std::wstring commandLine = L"\"" + enginePath + L"\" --service-host --json-lines";
    STARTUPINFOW startupInfo = {sizeof(startupInfo)};
    ZeroMemory(&g_childProcess, sizeof(g_childProcess));

    // CreateProcessW may write into the command line buffer; it must be
    // a mutable wchar_t array, not a string literal / const data pointer.
    std::wstring mutableCommandLine = commandLine;
    BOOL created = CreateProcessW(
        enginePath.c_str(), &mutableCommandLine[0], nullptr, nullptr, FALSE,
        CREATE_NO_WINDOW, nullptr, nullptr, &startupInfo, &g_childProcess);
    return created != FALSE;
}

void StopEngine() {
    if (g_childProcess.hProcess) {
        TerminateProcess(g_childProcess.hProcess, 0);
        WaitForSingleObject(g_childProcess.hProcess, 5000);
        CloseHandle(g_childProcess.hProcess);
        CloseHandle(g_childProcess.hThread);
        ZeroMemory(&g_childProcess, sizeof(g_childProcess));
    }
}

DWORD WINAPI ServiceCtrlHandler(DWORD controlCode, DWORD, LPVOID, LPVOID) {
    switch (controlCode) {
        case SERVICE_CONTROL_STOP:
        case SERVICE_CONTROL_SHUTDOWN:
            ReportStatus(SERVICE_STOP_PENDING, NO_ERROR, 6000);
            SetEvent(g_stopEvent);
            return NO_ERROR;
        default:
            return NO_ERROR;
    }
}

// Supervises the child: relaunches it if it exits while the service is
// still supposed to be running. A tight crash loop (child dies instantly,
// repeatedly) is throttled with a short backoff rather than spinning hot.
void SupervisorLoop() {
    if (!LaunchEngine()) {
        ReportStatus(SERVICE_STOPPED, ERROR_SERVICE_SPECIFIC_ERROR);
        return;
    }
    ReportStatus(SERVICE_RUNNING);

    while (true) {
        HANDLE waitHandles[2] = {g_stopEvent, g_childProcess.hProcess};
        DWORD waitResult = WaitForMultipleObjects(2, waitHandles, FALSE, INFINITE);

        if (waitResult == WAIT_OBJECT_0) {
            // Stop requested.
            StopEngine();
            break;
        }
        if (waitResult == WAIT_OBJECT_0 + 1) {
            // Child exited on its own -- relaunch unless we're stopping.
            CloseHandle(g_childProcess.hProcess);
            CloseHandle(g_childProcess.hThread);
            ZeroMemory(&g_childProcess, sizeof(g_childProcess));
            if (WaitForSingleObject(g_stopEvent, 2000) == WAIT_OBJECT_0) {
                break;
            }
            if (!LaunchEngine()) {
                break;
            }
        }
    }
    ReportStatus(SERVICE_STOPPED);
}

void WINAPI ServiceMain(DWORD, LPWSTR*) {
    g_statusHandle = RegisterServiceCtrlHandlerExW(kServiceName, ServiceCtrlHandler, nullptr);
    if (!g_statusHandle) return;

    g_status.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
    g_status.dwControlsAccepted = SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN;
    g_status.dwServiceSpecificExitCode = 0;
    ReportStatus(SERVICE_START_PENDING, NO_ERROR, 3000);

    g_stopEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    if (!g_stopEvent) {
        ReportStatus(SERVICE_STOPPED, ERROR_SERVICE_SPECIFIC_ERROR);
        return;
    }

    ConfigureServiceEnvironment();
    SupervisorLoop();
    CloseHandle(g_stopEvent);
}

}  // namespace

int wmain() {
    SERVICE_TABLE_ENTRYW serviceTable[] = {
        {const_cast<LPWSTR>(kServiceName), ServiceMain},
        {nullptr, nullptr},
    };
    if (!StartServiceCtrlDispatcherW(serviceTable)) {
        return static_cast<int>(GetLastError());
    }
    return 0;
}
