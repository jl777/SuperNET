#include <windows.h>

/// Performs a crash report and aborts.
void rust_seh_handler(DWORD exception_code);

long WINAPI veh_exception_filter(PEXCEPTION_POINTERS info)
{
    // https://docs.microsoft.com/en-us/windows/desktop/debug/using-a-vectored-exception-handler

    DWORD code = info->ExceptionRecord->ExceptionCode;

    // Don't handle the normal unwinding exceptions and panics.
    // cf. https://blogs.msdn.microsoft.com/oldnewthing/20100730-00/?p=13273
    if (code == 0xE06D7363) return EXCEPTION_CONTINUE_SEARCH;

    rust_seh_handler(code);

    // These instruction skips (?) are fishy, but they're only used in crash report unit tests.
    // In a non-`test` environment `rust_seh_handler` aborts.
#ifdef _AMD64_
    info->ContextRecord->Rip++;
#else
    info->ContextRecord->Eip++;
#endif

    return EXCEPTION_CONTINUE_EXECUTION;
}

void init_veh()
{
    AddVectoredExceptionHandler(1, &veh_exception_filter);
}
