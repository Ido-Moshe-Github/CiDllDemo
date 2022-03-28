#include <ntifs.h>
#include "SignatureCheck.h"

EXTERN_C DRIVER_INITIALIZE DriverEntry;

#ifndef LOG
#define LOG(Format, ...) DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[CiDemoDriver] " Format " \n", __VA_ARGS__)
#endif

void ProcessCreateProcessNotifyRoutineEx(
    _Inout_ PEPROCESS Process,
    _In_ HANDLE ProcessId,
    _Inout_opt_ PPS_CREATE_NOTIFY_INFO CreateInfo
)
{
    UNREFERENCED_PARAMETER(Process);
    UNREFERENCED_PARAMETER(ProcessId);
    UNREFERENCED_PARAMETER(CreateInfo);

    do
    {
        if (KeGetCurrentIrql() > PASSIVE_LEVEL)
        {
            break;
        }

        if (CreateInfo == nullptr)
        {
            break; // process died
        }

#if (NTDDI_VERSION >= NTDDI_WIN10)
        if (CreateInfo->FileObject != nullptr)
        {
            ValidateFileUsingFileObject(CreateInfo->FileObject);
            break;
        }
#endif // NTDDI_VERSION >= NTDDI_WIN10

        if (CreateInfo->ImageFileName != nullptr)
        {
            ValidateFileUsingFileName(CreateInfo->ImageFileName);
            break;
        }

    } while (false);
}

VOID MyDriverUnload(
    _In_ PDRIVER_OBJECT DriverObject
)
{
    UNREFERENCED_PARAMETER(DriverObject);

    PsSetCreateProcessNotifyRoutineEx(ProcessCreateProcessNotifyRoutineEx, TRUE);

    LOG("Unload");
}

NTSTATUS DriverEntry(
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PUNICODE_STRING RegistryPath
)
{
    UNREFERENCED_PARAMETER(DriverObject);
    UNREFERENCED_PARAMETER(RegistryPath);

    NTSTATUS Status = STATUS_SUCCESS;

    LOG("Load");

    do
    {
        Status = PsSetCreateProcessNotifyRoutineEx(ProcessCreateProcessNotifyRoutineEx, FALSE);
        if (!NT_SUCCESS(Status))
        {
            LOG("Failed to register callback with status %d", Status);
            break;
        }

        DriverObject->DriverUnload = MyDriverUnload;

    } while (false);

    return Status;
}
