// PingScanGui.cpp
// Win11 原生 Win32 C++ GUI 版本：对应 ping_scan.py
// 行为：并行扫描 192.168.1.1 ~ 192.168.1.255（50 并发，ICMP 超时 1000ms），
//       实时输出可达主机，结束后执行 arp -a 并显示结果。

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winsock2.h>
#include <iphlpapi.h>
#include <icmpapi.h>

#include <atomic>
#include <iomanip>
#include <memory>
#include <mutex>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "Ws2_32.lib")
#pragma comment(lib, "user32.lib")
#pragma comment(lib, "gdi32.lib")

namespace {

const wchar_t* kNetworkPrefix = L"192.168.1";
const int kStartIp = 1;
const int kEndIp = 255;
const int kMaxWorkers = 50;
const DWORD kPingTimeoutMs = 1000;
const int kTotal = kEndIp - kStartIp + 1;

const int IDC_START = 1001;
const int IDC_RESET = 1002;
const int IDC_OUTPUT = 1003;
const int IDC_INFO = 1004;

const UINT WM_APPEND = WM_APP + 1;
const UINT WM_DONE = WM_APP + 2;

HWND g_hStart = nullptr;
HWND g_hReset = nullptr;
HWND g_hOutput = nullptr;
HWND g_hInfo = nullptr;
HFONT g_hFont = nullptr;

std::atomic<bool> g_cancel{false};
std::atomic<UINT> g_generation{0};
bool g_running = false;     // 仅 UI 线程读写

struct ScanContext {
    std::atomic<int> next{kStartIp};
    std::atomic<int> done{0};
    std::atomic<int> alive{0};
    UINT generation = 0;
    HWND hwnd = nullptr;
    std::mutex reachableMutex;
    std::vector<std::wstring> reachable;
};

void SetFont(HWND control) {
    if (g_hFont) SendMessageW(control, WM_SETFONT, reinterpret_cast<WPARAM>(g_hFont), TRUE);
}

void AppendText(HWND edit, const std::wstring& text) {
    SendMessageW(edit, EM_SETSEL, static_cast<WPARAM>(-1), static_cast<LPARAM>(-1));
    SendMessageW(edit, EM_REPLACESEL, FALSE, reinterpret_cast<LPARAM>(text.c_str()));
    SendMessageW(edit, EM_SCROLLCARET, 0, 0);
}

void PostOutput(HWND hwnd, UINT generation, const std::wstring& text) {
    std::wstring line = text;
    if (line.empty() || line.back() != L'\n') line += L"\r\n";
    auto* heapText = new std::wstring(line);
    if (!PostMessageW(hwnd, WM_APPEND, static_cast<WPARAM>(generation),
                      reinterpret_cast<LPARAM>(heapText))) {
        delete heapText;
    }
}

std::wstring WideIp(int host) {
    return std::wstring(kNetworkPrefix) + L"." + std::to_wstring(host);
}

bool PingWithHandle(HANDLE icmp, int host) {
    const std::string ip = "192.168.1." + std::to_string(host);
    const IPAddr destination = inet_addr(ip.c_str());
    if (destination == INADDR_NONE) return false;

    char request[32] = {};
    std::vector<BYTE> reply(sizeof(ICMP_ECHO_REPLY) + sizeof(request) + 8);
    DWORD count = IcmpSendEcho(icmp, destination, request, sizeof(request), nullptr,
                               reply.data(), static_cast<DWORD>(reply.size()), kPingTimeoutMs);
    if (count == 0) return false;

    auto* echo = reinterpret_cast<ICMP_ECHO_REPLY*>(reply.data());
    return echo->Status == IP_SUCCESS;
}

void Worker(std::shared_ptr<ScanContext> ctx) {
    HANDLE icmp = IcmpCreateFile();
    if (icmp == INVALID_HANDLE_VALUE) {
        PostOutput(ctx->hwnd, ctx->generation, L"[错误] 无法创建 ICMP 句柄，请检查网络权限。");
        return;
    }

    for (;;) {
        if (g_cancel.load()) break;
        const int host = ctx->next.fetch_add(1);
        if (host > kEndIp) break;

        const bool alive = PingWithHandle(icmp, host);
        const int finished = ctx->done.fetch_add(1) + 1;

        if (alive) {
            ctx->alive.fetch_add(1);
            {
                std::lock_guard<std::mutex> lock(ctx->reachableMutex);
                ctx->reachable.push_back(WideIp(host));
            }
            std::wostringstream line;
            line << L"[" << std::setw(3) << finished << L"/" << kTotal << L"] "
                 << L"\x2713 " << WideIp(host) << L" 可达";
            PostOutput(ctx->hwnd, ctx->generation, line.str());
        }

        if (finished % 20 == 0) {
            std::wostringstream line;
            line << L"[" << std::setw(3) << finished << L"/" << kTotal << L"] 进度: "
                 << finished << L"/" << kTotal << L" (已发现 " << ctx->alive.load()
                 << L" 个可达)";
            PostOutput(ctx->hwnd, ctx->generation, line.str());
        }
    }

    IcmpCloseHandle(icmp);
}

std::wstring ConvertGBKToWide(const std::string& bytes) {
    if (bytes.empty()) return L"";
    int length = MultiByteToWideChar(936, 0, bytes.data(), static_cast<int>(bytes.size()), nullptr, 0);
    if (length <= 0) return L"[提示] arp -a 输出解码失败。";
    std::wstring result(static_cast<size_t>(length), L'\0');
    MultiByteToWideChar(936, 0, bytes.data(), static_cast<int>(bytes.size()), result.data(), length);
    return result;
}

void RunArp(HWND hwnd, UINT generation) {
    SECURITY_ATTRIBUTES sa = {};
    sa.nLength = sizeof(sa);
    sa.bInheritHandle = TRUE;
    HANDLE readPipe = nullptr;
    HANDLE writePipe = nullptr;
    if (!CreatePipe(&readPipe, &writePipe, &sa, 0)) {
        PostOutput(hwnd, generation, L"[错误] 无法创建 arp 输出管道。");
        return;
    }

    STARTUPINFOW si = {};
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;
    si.hStdOutput = writePipe;
    si.hStdError = writePipe;
    PROCESS_INFORMATION pi = {};
    wchar_t commandLine[] = L"arp -a";

    if (!CreateProcessW(nullptr, commandLine, nullptr, nullptr, TRUE, CREATE_NO_WINDOW,
                        nullptr, nullptr, &si, &pi)) {
        PostOutput(hwnd, generation, L"[错误] 执行 arp -a 失败。");
        CloseHandle(readPipe);
        CloseHandle(writePipe);
        return;
    }

    CloseHandle(writePipe);
    std::string output;
    char buffer[1024];
    for (;;) {
        DWORD read = 0;
        if (!ReadFile(readPipe, buffer, sizeof(buffer), &read, nullptr) || read == 0) break;
        output.append(buffer, read);
    }
    WaitForSingleObject(pi.hProcess, INFINITE);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    CloseHandle(readPipe);

    PostOutput(hwnd, generation, ConvertGBKToWide(output));
}

struct DoneGuard {
    HWND hwnd;
    UINT generation;
    ~DoneGuard() { PostMessageW(hwnd, WM_DONE, static_cast<WPARAM>(generation), 0); }
};

void RunScan(std::shared_ptr<ScanContext> ctx) {
    DoneGuard done{ctx->hwnd, ctx->generation};

    std::vector<std::thread> workers;
    workers.reserve(kMaxWorkers);
    for (int i = 0; i < kMaxWorkers; ++i) {
        workers.emplace_back(Worker, ctx);
    }
    for (auto& worker : workers) {
        if (worker.joinable()) worker.join();
    }

    if (g_cancel.load() || ctx->generation != g_generation) return;

    PostOutput(ctx->hwnd, ctx->generation, L"==================================================");
    PostOutput(ctx->hwnd, ctx->generation, L"扫描完成！");
    {
        std::wostringstream line;
        line << L"  可达 IP 数量: " << ctx->alive.load();
        PostOutput(ctx->hwnd, ctx->generation, line.str());
    }
    {
        std::wostringstream line;
        line << L"  不可达 IP 数量: " << (kTotal - ctx->alive.load());
        PostOutput(ctx->hwnd, ctx->generation, line.str());
    }
    PostOutput(ctx->hwnd, ctx->generation, L"");

    if (!ctx->reachable.empty()) {
        PostOutput(ctx->hwnd, ctx->generation, L"可达 IP 列表：");
        std::lock_guard<std::mutex> lock(ctx->reachableMutex);
        for (const auto& ip : ctx->reachable) {
            PostOutput(ctx->hwnd, ctx->generation, L"  \x2713 " + ip);
        }
    } else {
        PostOutput(ctx->hwnd, ctx->generation, L"没有发现可达 IP。");
    }

    PostOutput(ctx->hwnd, ctx->generation, L"");
    PostOutput(ctx->hwnd, ctx->generation, L"==================================================");
    PostOutput(ctx->hwnd, ctx->generation, L"执行 arp -a ...");
    PostOutput(ctx->hwnd, ctx->generation, L"==================================================");
    RunArp(ctx->hwnd, ctx->generation);
}

LRESULT CALLBACK WndProc(HWND hwnd, UINT message, WPARAM wParam, LPARAM lParam) {
    switch (message) {
        case WM_CREATE: {
            HINSTANCE instance = GetModuleHandleW(nullptr);
            g_hFont = CreateFontW(-14, 0, 0, 0, FW_NORMAL, 0, 0, 0, DEFAULT_CHARSET,
                                  OUT_TT_PRECIS, CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY,
                                  DEFAULT_PITCH | FF_DONTCARE, L"Microsoft YaHei UI");

            g_hStart = CreateWindowW(L"Button", L"开始扫描",
                                     WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_DEFPUSHBUTTON,
                                     20, 20, 110, 34, hwnd, reinterpret_cast<HMENU>(static_cast<INT_PTR>(IDC_START)),
                                     instance, nullptr);
            g_hReset = CreateWindowW(L"Button", L"重置",
                                     WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_PUSHBUTTON,
                                     142, 20, 90, 34, hwnd, reinterpret_cast<HMENU>(static_cast<INT_PTR>(IDC_RESET)),
                                     instance, nullptr);
            g_hInfo = CreateWindowW(L"Static",
                                    L"扫描范围: 192.168.1.1 ~ 192.168.1.255    并发线程: 50    ICMP 超时: 1000ms",
                                    WS_CHILD | WS_VISIBLE | SS_LEFT,
                                    252, 27, 560, 24, hwnd, reinterpret_cast<HMENU>(static_cast<INT_PTR>(IDC_INFO)),
                                    instance, nullptr);
            g_hOutput = CreateWindowExW(WS_EX_CLIENTEDGE, L"Edit", nullptr,
                                        WS_CHILD | WS_VISIBLE | WS_TABSTOP | WS_VSCROLL |
                                        WS_HSCROLL | ES_MULTILINE | ES_READONLY |
                                        ES_AUTOVSCROLL | ES_WANTRETURN,
                                        20, 70, 780, 450, hwnd, reinterpret_cast<HMENU>(static_cast<INT_PTR>(IDC_OUTPUT)),
                                        instance, nullptr);

            SetFont(g_hStart);
            SetFont(g_hReset);
            SetFont(g_hInfo);
            SetFont(g_hOutput);
            SendMessageW(g_hOutput, EM_LIMITTEXT, 0x00100000, 0);
            AppendText(g_hOutput,
                       L"[就绪] 点击“开始扫描”执行 192.168.1.1 ~ 192.168.1.255 的并行 ping 扫描，"
                       L"结束后自动执行 arp -a。\r\n");
            return 0;
        }

        case WM_COMMAND: {
            const int controlId = LOWORD(wParam);
            if (controlId == IDC_START && !g_running) {
                ++g_generation;
                g_cancel.store(false);
                g_running = true;
                EnableWindow(g_hStart, FALSE);
                SetWindowTextW(g_hOutput, L"");
                std::wostringstream header;
                header << L"开始扫描 " << kNetworkPrefix << L"." << kStartIp << L" ~ "
                       << kNetworkPrefix << L"." << kEndIp << L" ...\r\n"
                       << L"并发线程数: " << kMaxWorkers << L"\r\n"
                       << L"==================================================\r\n";
                AppendText(g_hOutput, header.str());

                auto ctx = std::make_shared<ScanContext>();
                ctx->generation = g_generation;
                ctx->hwnd = hwnd;
                std::thread(RunScan, ctx).detach();
                return 0;
            }
            if (controlId == IDC_RESET) {
                ++g_generation;                 // 使在途异步输出失效
                g_cancel.store(true);           // 通知工作线程停止
                SetWindowTextW(g_hOutput, L"");
                AppendText(g_hOutput, L"[重置] 输出已清空，扫描请求已取消。\r\n");
                if (!g_running) EnableWindow(g_hStart, TRUE);
                return 0;
            }
            break;
        }

        case WM_APPEND: {
            auto* text = reinterpret_cast<std::wstring*>(lParam);
            if (wParam == g_generation) AppendText(g_hOutput, *text);
            delete text;
            return 0;
        }

        case WM_DONE: {
            g_running = false;
            EnableWindow(g_hStart, TRUE);
            if (wParam == g_generation) {
                AppendText(g_hOutput, L"\r\n[完成] 所有结果已输出。\r\n");
            }
            return 0;
        }

        case WM_SIZE: {
            if (wParam == SIZE_MINIMIZED) return 0;
            RECT client = {};
            GetClientRect(hwnd, &client);
            const int width = client.right > 60 ? client.right - 40 : 1;
            const int height = client.bottom > 100 ? client.bottom - 90 : 1;
            MoveWindow(g_hOutput, 20, 70, width, height, TRUE);
            MoveWindow(g_hInfo, 252, 27, client.right > 272 ? client.right - 272 : 1, 24, TRUE);
            return 0;
        }

        case WM_GETMINMAXINFO: {
            auto* info = reinterpret_cast<MINMAXINFO*>(lParam);
            info->ptMinTrackSize.x = 640;
            info->ptMinTrackSize.y = 420;
            return 0;
        }

        case WM_DESTROY: {
            g_cancel.store(true);
            if (g_hFont) DeleteObject(g_hFont);
            PostQuitMessage(0);
            return 0;
        }
    }
    return DefWindowProcW(hwnd, message, wParam, lParam);
}

}  // namespace

int WINAPI wWinMain(HINSTANCE instance, HINSTANCE, PWSTR, int showCommand) {
    SetProcessDPIAware();

    WNDCLASSEXW windowClass = {};
    windowClass.cbSize = sizeof(windowClass);
    windowClass.lpfnWndProc = WndProc;
    windowClass.hInstance = instance;
    windowClass.hCursor = LoadCursorW(nullptr, IDC_ARROW);
    windowClass.hbrBackground = reinterpret_cast<HBRUSH>(COLOR_WINDOW + 1);
    windowClass.lpszClassName = L"PingScanGuiClass";
    if (!RegisterClassExW(&windowClass)) return 1;

    HWND hwnd = CreateWindowExW(0, L"PingScanGuiClass", L"Ping 扫描器 - 192.168.1.x",
                                WS_OVERLAPPEDWINDOW, CW_USEDEFAULT, CW_USEDEFAULT,
                                840, 560, nullptr, nullptr, instance, nullptr);
    if (!hwnd) return 1;

    ShowWindow(hwnd, showCommand);
    UpdateWindow(hwnd);

    MSG message = {};
    while (GetMessageW(&message, nullptr, 0, 0) > 0) {
        TranslateMessage(&message);
        DispatchMessageW(&message);
    }
    return static_cast<int>(message.wParam);
}
