#include <windows.h>

void rust_seh_handler (u32);

void c_access_violation()
{
    // Straight from the https://docs.microsoft.com/en-us/windows/desktop/Debug/using-a-vectored-exception-handler.
    char *ptr = 0;
    *ptr = 0;
}

/// Runs the given callback withing the __try/__except block, allowing us to catch segmentation faults on Windows.
///
/// Invokes `rust_seh_handler` whenever a Structured Exception is caught.
void with_seh (void (*cb)())
{
    __try
    {
        cb();
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        // https://docs.microsoft.com/en-us/windows/desktop/debug/getexceptioncode
        rust_seh_handler (GetExceptionCode());
    }
}
