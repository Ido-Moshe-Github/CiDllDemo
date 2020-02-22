#include <ntddk.h> // PsSetCreateProcessNotifyRoutineEx
#include <wdm.h>
#include "SignatureCheck.h"


DRIVER_UNLOAD MyDriverUnload;
void registerProcessCallback();
void unregisterProcessCallback();
void ProcessCreateProcessNotifyRoutineEx(PEPROCESS Process, HANDLE ProcessId, PPS_CREATE_NOTIFY_INFO CreateInfo);

extern "C" NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
    UNREFERENCED_PARAMETER(DriverObject);
    UNREFERENCED_PARAMETER(RegistryPath);
    DriverObject->DriverUnload = MyDriverUnload;

    KdPrint(("CiDemoDriver load\n"));

    registerProcessCallback();

    return STATUS_SUCCESS;
}

VOID MyDriverUnload(_In_ struct _DRIVER_OBJECT* DriverObject)
{
    UNREFERENCED_PARAMETER(DriverObject);
    KdPrint(("CiDemoDriver unload\n"));
    unregisterProcessCallback();
}

void registerProcessCallback()
{
    const NTSTATUS registerCallbackStatus = PsSetCreateProcessNotifyRoutineEx(ProcessCreateProcessNotifyRoutineEx, FALSE);
    if (!NT_SUCCESS(registerCallbackStatus))
    {
        KdPrint(("failed to register callback with status %d\n", registerCallbackStatus));
    }
    else
    {
        KdPrint(("successfully registered callback\n"));
    }
}

void unregisterProcessCallback()
{
    const NTSTATUS registerCallbackStatus = PsSetCreateProcessNotifyRoutineEx(ProcessCreateProcessNotifyRoutineEx, TRUE);
    if (!NT_SUCCESS(registerCallbackStatus))
    {
        KdPrint(("failed to unregister callback\n"));
    }
    else
    {
        KdPrint(("successfully unregistered callback\n"));
    }
}

void ProcessCreateProcessNotifyRoutineEx(
    PEPROCESS Process,
    HANDLE ProcessId,
    PPS_CREATE_NOTIFY_INFO CreateInfo
)
{
    UNREFERENCED_PARAMETER(Process);
    UNREFERENCED_PARAMETER(ProcessId);

    if (CreateInfo == nullptr) return; //process died

    if (CreateInfo->FileObject == nullptr) return;
    if (nullptr == CreateInfo->ImageFileName) return;

    KdPrint(("New process - image name: %wZ\n", CreateInfo->ImageFileName));

    validateFileUsingCiValidateFileObject(CreateInfo->FileObject);
    validateFileUsingCiCheckSignedFile(CreateInfo->ImageFileName);
}
