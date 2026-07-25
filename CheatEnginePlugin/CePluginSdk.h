#pragma once

#include <Windows.h>

#include <cstddef>

// 中文说明：本文件只描述 KSword 桥接插件实际使用的 Cheat Engine SDK v6 ABI 前缀。
// 字段顺序依据 Cheat Engine 官方 cepluginsdk.h；不复制 Lua 或 UI 扩展定义。
namespace ksword::ce
{
    constexpr unsigned int kCeSdkVersion = 6U;

    struct PluginVersion
    {
        unsigned int version; // version：插件要求的最低 CE SDK 版本。
        char* pluginName;      // pluginName：DLL 生命周期内有效的 NUL 结尾名称。
    };

    enum class PluginType : int
    {
        addressList = 0,
        memoryView = 1,
        onDebugEvent = 2,
        processWatcherEvent = 3,
        functionPointerChange = 4,
        mainMenu = 5,
        disassemblerContext = 6,
        disassemblerRenderLine = 7,
        autoAssembler = 8
    };

    using ShowMessageFunction = void(__stdcall*)(char* message);
    using RegisterFunction = int(__stdcall*)(
        int pluginId,
        PluginType functionType,
        void* initialization);
    using UnregisterFunction = BOOL(__stdcall*)(int pluginId, int functionId);
    using GetMainWindowHandleFunction = HANDLE(__stdcall*)();

    // 中文说明：以下占位函数类型只用于维持 ABI 字段宽度，插件不会调用它们。
    using GenericFunction = void(__stdcall*)();
    using ReadProcessMemoryFunction = BOOL(WINAPI*)(
        HANDLE processHandle,
        LPCVOID baseAddress,
        LPVOID buffer,
        SIZE_T bytesToRead,
        SIZE_T* bytesRead);
    using WriteProcessMemoryFunction = BOOL(WINAPI*)(
        HANDLE processHandle,
        LPVOID baseAddress,
        LPCVOID buffer,
        SIZE_T bytesToWrite,
        SIZE_T* bytesWritten);
    using OpenProcessFunction = HANDLE(WINAPI*)(
        DWORD desiredAccess,
        BOOL inheritHandle,
        DWORD processId);
    using VirtualQueryExFunction = SIZE_T(WINAPI*)(
        HANDLE processHandle,
        LPCVOID address,
        PMEMORY_BASIC_INFORMATION information,
        SIZE_T informationLength);

    using FunctionPointerChangeCallback = void(__stdcall*)(int reserved);

    struct FunctionPointerChangeInitialization
    {
        FunctionPointerChangeCallback callbackRoutine; // callbackRoutine：CE 重建函数表后的通知。
    };

    // 中文说明：结构必须与官方 ExportedFunctions 从首字段到 VirtualQueryEx 保持同序。
    // sizeofExportedFunctions 仅用于验证 CE 至少提供了本插件要访问的字段。
    struct ExportedFunctions
    {
        int sizeofExportedFunctions;
        ShowMessageFunction showMessage;
        RegisterFunction registerFunction;
        UnregisterFunction unregisterFunction;
        ULONG* openedProcessId;
        HANDLE* openedProcessHandle;
        GetMainWindowHandleFunction getMainWindowHandle;
        GenericFunction autoAssemble;
        GenericFunction assembler;
        GenericFunction disassembler;
        GenericFunction changeRegistersAtAddress;
        GenericFunction injectDll;
        GenericFunction freezeMemory;
        GenericFunction unfreezeMemory;
        GenericFunction fixMemory;
        GenericFunction processList;
        GenericFunction reloadSettings;
        GenericFunction getAddressFromPointer;
        ReadProcessMemoryFunction* readProcessMemory;
        void* writeProcessMemory;
        void* getThreadContext;
        void* setThreadContext;
        void* suspendThread;
        void* resumeThread;
        void* openProcess;
        void* waitForDebugEvent;
        void* continueDebugEvent;
        void* debugActiveProcess;
        void* stopDebugging;
        void* stopRegisterChange;
        void* virtualProtect;
        void* virtualProtectEx;
        void* virtualQueryEx;
    };

    constexpr std::size_t kRequiredExportedFunctionsSize =
        offsetof(ExportedFunctions, virtualQueryEx) + sizeof(void*);
}
