#include <windows.h>

extern "C" __declspec(dllexport) NTSTATUS _stdcall CiCheckSignedFile(
    const PVOID digestBuffer,
    int digestSize,
    int digestIdentifier,
    const PVOID winCert,
    int sizeOfSecurityDirectory,
    PVOID policyInfoForSigner,
    PVOID signingTime,
    PVOID policyInfoForTimestampingAuthority)
{
    NTSTATUS dummyReturnValue = 0;
    return dummyReturnValue;
}

extern "C" __declspec(dllexport) PVOID _stdcall CiFreePolicyInfo(PVOID policyInfoPtr)
{
    PVOID dummyReturnValue = nullptr;
    return dummyReturnValue;
}

extern "C" __declspec(dllexport) NTSTATUS _stdcall CiValidateFileObject(
    PVOID fileObject,
    int a2,
    int a3,
    PVOID policyInfoForSigner,
    PVOID policyInfoForTimestampingAuthority,
    LARGE_INTEGER * signingTime,
    BYTE * digestBuffer,
    int* digestSize,
    int* digestIdentifier
)
{
    NTSTATUS dummyReturnValue = 0;
    return dummyReturnValue;
}