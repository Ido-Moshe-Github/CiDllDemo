/*
 * PROJECT:   https://github.com/Ido-Moshe-Github/CiDllDemo
 * FILE:      SignatureCheck.cpp
 * PURPOSE:   Definition for the ci.dll API and Struct.
 *
 * LICENSE:   Relicensed under The MIT License from The CC BY 4.0 License
 *
 * DEVELOPER: [Ido Moshe, Liron Zuarets, MiroKaku]
 *
 */

#include <ntifs.h>
#include <ntimage.h>
#include "ci.h"
#include "SignatureCheck.h"

#pragma warning(disable: 4996)

#ifndef LOG
#define LOG(Format, ...) DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[CiDemoDriver][" __FUNCTION__ "] " Format " \n", __VA_ARGS__)
#endif

//
// copy from https://github.com/MiroKaku/Veil
//
// begin
#ifndef ANSI_STRING_MAX_BYTES
#define ANSI_STRING_MAX_BYTES ((USHORT)65535)
#endif // ANSI_STRING_MAX_BYTES

#ifndef ANSI_STRING_MAX_CHARS
#define ANSI_STRING_MAX_CHARS ANSI_STRING_MAX_BYTES
#endif

#if (NTDDI_VERSION >= NTDDI_WIN10_VB)
_When_(AllocateDestinationString,
    _At_(DestinationString->MaximumLength, _Out_range_(<= , (SourceString->MaximumLength / sizeof(WCHAR)))))
    _When_(!AllocateDestinationString,
        _At_(DestinationString->Buffer, _Const_)
        _At_(DestinationString->MaximumLength, _Const_))
    _IRQL_requires_max_(PASSIVE_LEVEL)
    _When_(AllocateDestinationString, _Must_inspect_result_)
    NTSYSAPI
    NTSTATUS
    NTAPI
    RtlUnicodeStringToUTF8String(
        _When_(AllocateDestinationString, _Out_ _At_(DestinationString->Buffer, __drv_allocatesMem(Mem)))
        _When_(!AllocateDestinationString, _Inout_)
        PUTF8_STRING DestinationString,
        _In_ PCUNICODE_STRING SourceString,
        _In_ BOOLEAN AllocateDestinationString
    );

_IRQL_requires_max_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSYSAPI
NTSTATUS
NTAPI
RtlUTF8StringToUnicodeString(
    _When_(AllocateDestinationString, _Out_ _At_(DestinationString->Buffer, __drv_allocatesMem(Mem)))
    _When_(!AllocateDestinationString, _Inout_)
    PUNICODE_STRING DestinationString,
    _In_ PUTF8_STRING SourceString,
    _In_ BOOLEAN AllocateDestinationString
);

#else // NTDDI_VERSION >= NTDDI_WIN10_VB

_When_(AllocateDestinationString,
    _At_(DestinationString->MaximumLength, _Out_range_(<= , (SourceString->MaximumLength / sizeof(WCHAR)))))
    _When_(!AllocateDestinationString,
        _At_(DestinationString->Buffer, _Const_)
        _At_(DestinationString->MaximumLength, _Const_))
    _IRQL_requires_max_(PASSIVE_LEVEL)
    _When_(AllocateDestinationString, _Must_inspect_result_)
    FORCEINLINE
    NTSTATUS
    NTAPI
    RtlUnicodeStringToUTF8String(
        _When_(AllocateDestinationString, _Out_ _At_(DestinationString->Buffer, __drv_allocatesMem(Mem)))
        _When_(!AllocateDestinationString, _Inout_)
        PUTF8_STRING DestinationString,
        _In_ PCUNICODE_STRING SourceString,
        _In_ BOOLEAN AllocateDestinationString
    )
{
    NTSTATUS Status = STATUS_SUCCESS;

    do
    {
        ULONG ActualByteCount = 0ul;

        Status = RtlUnicodeToUTF8N(NULL, 0, &ActualByteCount, SourceString->Buffer, SourceString->Length);
        if (ActualByteCount == 0ul)
        {
            break;
        }

        ActualByteCount += sizeof ANSI_NULL;

        if (ActualByteCount >= ANSI_STRING_MAX_BYTES)
        {
            return STATUS_INVALID_PARAMETER_2;
        }

        if (AllocateDestinationString)
        {
            DestinationString->Buffer = (PSTR)ExAllocatePool(PagedPool, ActualByteCount);
            if (DestinationString->Buffer == NULL)
            {
                Status = STATUS_NO_MEMORY;
                break;
            }
            DestinationString->MaximumLength = (USHORT)ActualByteCount;

            RtlSecureZeroMemory(DestinationString->Buffer, ActualByteCount);
        }
        else
        {
            if (DestinationString->MaximumLength < ActualByteCount)
            {
                Status = STATUS_BUFFER_OVERFLOW;
                break;
            }
        }

        Status = RtlUnicodeToUTF8N(DestinationString->Buffer, DestinationString->MaximumLength, &ActualByteCount, SourceString->Buffer, SourceString->Length);
        if (!NT_SUCCESS(Status))
        {
            if (AllocateDestinationString)
            {
                RtlFreeAnsiString(DestinationString);
            }
            break;
        }

        if (ActualByteCount > DestinationString->MaximumLength)
        {
            Status = STATUS_BUFFER_OVERFLOW;
            break;
        }

        DestinationString->Length = (USHORT)ActualByteCount;
        DestinationString->Buffer[ActualByteCount / sizeof ANSI_NULL] = ANSI_NULL;

    } while (false);

    return Status;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
_Must_inspect_result_
FORCEINLINE
NTSTATUS
NTAPI
RtlUTF8StringToUnicodeString(
    _When_(AllocateDestinationString, _Out_ _At_(DestinationString->Buffer, __drv_allocatesMem(Mem)))
    _When_(!AllocateDestinationString, _Inout_)
    PUNICODE_STRING DestinationString,
    _In_ PUTF8_STRING SourceString,
    _In_ BOOLEAN AllocateDestinationString
)
{
    NTSTATUS Status = STATUS_SUCCESS;

    do
    {
        ULONG ActualByteCount = 0ul;

        Status = RtlUTF8ToUnicodeN(NULL, 0, &ActualByteCount, SourceString->Buffer, SourceString->Length);
        if (ActualByteCount == 0ul)
        {
            break;
        }

        ActualByteCount += sizeof UNICODE_NULL;

        if (ActualByteCount >= UNICODE_STRING_MAX_BYTES)
        {
            return STATUS_INVALID_PARAMETER_2;
        }

        if (AllocateDestinationString)
        {
            DestinationString->Buffer = (PWCH)ExAllocatePool(PagedPool, ActualByteCount);
            if (DestinationString->Buffer == NULL)
            {
                Status = STATUS_NO_MEMORY;
                break;
            }
            DestinationString->MaximumLength = (USHORT)ActualByteCount;

            RtlSecureZeroMemory(DestinationString->Buffer, ActualByteCount);
        }
        else
        {
            if (DestinationString->MaximumLength < ActualByteCount)
            {
                Status = STATUS_BUFFER_OVERFLOW;
                break;
            }
        }

        Status = RtlUTF8ToUnicodeN(DestinationString->Buffer, DestinationString->MaximumLength, &ActualByteCount, SourceString->Buffer, SourceString->Length);
        if (!NT_SUCCESS(Status))
        {
            if (AllocateDestinationString)
            {
                RtlFreeUnicodeString(DestinationString);
            }
            break;
        }

        if (ActualByteCount > DestinationString->MaximumLength)
        {
            Status = STATUS_BUFFER_OVERFLOW;
            break;
        }

        DestinationString->Length = (USHORT)ActualByteCount;
        DestinationString->Buffer[ActualByteCount / sizeof UNICODE_NULL] = UNICODE_NULL;

    } while (false);

    return Status;
}
#endif //NTDDI_VERSION < NTDDI_WIN10_VB
// end


const char* AlgIdToString(
    _In_ ALG_ID AlgId
)
{
    switch (AlgId)
    {
    default:
        return "unknown";

    case CALG_SHA1:
        return "SHA1";

    case CALG_SHA_256:
        return "SHA256";
    }
}

#if (NTDDI_VERSION >= NTDDI_WIN10)
void PrintPolicyInfo(
    _In_ const MINCRYPT_POLICY_INFO* PolicyInfo
)
{
    if (PolicyInfo->Size == 0)
    {
        LOG("policy info is empty");
        return;
    }

    if (PolicyInfo->ChainInfo == nullptr)
    {
        LOG("PolicyInfo->ChainInfo is null");
        return;
    }

    const MINCRYPT_CHAIN_INFO* ChainInfo = PolicyInfo->ChainInfo;
    const MINCRYPT_CHAIN_ELEMENT* ChainElements = ChainInfo->ChainElements;

    if (ChainInfo->Size < sizeof(MINCRYPT_CHAIN_INFO) ||
        ChainInfo->NumberOfChainElement == 0)
    {
        LOG("PolicyInfo->ChainInfo is too small.");
        return;
    }

    const char* Indentation[] =
    {
        ">",
        "  >",
        "    >",
        "      >",
        "        >",
        "          >",
    };

    for (size_t i = ChainInfo->NumberOfChainElement, j = 0u; i > 0u; --i, ++j)
    {
        const MINCRYPT_CHAIN_ELEMENT* Element = &ChainElements[i - 1];

        UTF8_STRING SubjectU8 = {};
        SubjectU8.Buffer = Element->Subject.Data;
        SubjectU8.Length = Element->Subject.Size;
        SubjectU8.MaximumLength = SubjectU8.Length;

        UNICODE_STRING Subject = {};
        if (NT_SUCCESS(RtlUTF8StringToUnicodeString(&Subject, &SubjectU8, TRUE)))
        {
            LOG("%s Cert: size - %u, algorithm - %s, subject - %wZ",
                Indentation[j],
                Element->Certificate.Size,
                AlgIdToString(Element->HashAlgId),
                &Subject);

            RtlFreeUnicodeString(&Subject);
        }
    }
}

void PrintPolicyInfoLegacyMode(
    _In_ const MINCRYPT_POLICY_INFO* PolicyInfo
)
{
    if (PolicyInfo->Size == 0)
    {
        LOG("policy info is empty");
        return;
    }

    if (PolicyInfo->ChainInfo == nullptr)
    {
        LOG("PolicyInfo->ChainInfo is null");
        return;
    }

    const MINCRYPT_CHAIN_INFO* ChainInfo = PolicyInfo->ChainInfo;
    const MINCRYPT_CHAIN_ELEMENT* ChainElements = ChainInfo->ChainElements;

    if (ChainInfo->Size < sizeof(MINCRYPT_CHAIN_INFO) ||
        ChainInfo->NumberOfChainElement == 0)
    {
        LOG("PolicyInfo->ChainInfo is too small.");
        return;
    }

    const char* Indentation[] =
    {
        ">",
        "  >",
        "    >",
        "      >",
        "        >",
        "          >",
    };

    for (size_t i = ChainInfo->NumberOfChainElement, j = 0u; i > 0u; --i, ++j)
    {
        const MINCRYPT_CHAIN_ELEMENT* Element = &ChainElements[i - 1];

        UNICODE_STRING Subject = {};

        if (NT_SUCCESS(CiGetCertPublisherName((MINCERT_BLOB*)&Element->Certificate,
            [](SIZE_T Bytes) { return ExAllocatePool(PagedPool, Bytes); }, &Subject)))
        {
            LOG("%s Cert: size - %u, algorithm - %s, publisher - %wZ",
                Indentation[j],
                Element->Certificate.Size,
                AlgIdToString(Element->HashAlgId),
                &Subject);

            RtlFreeUnicodeString(&Subject);
        }
    }
}
#endif // NTDDI_VERSION >= NTDDI_WIN10

NTSTATUS ValidateFileLegacyMode(
    _In_  HANDLE                FileHandle,
    _In_  PVOID                 Hash,
    _In_  UINT32                HashSize,
    _In_  ALG_ID                HashAlgId,
    _In_  IMAGE_DATA_DIRECTORY* SecurityDirectory,
    _Out_ MINCRYPT_POLICY_INFO* PolicyInfo,
    _Out_ LARGE_INTEGER* SigningTime,
    _Out_ MINCRYPT_POLICY_INFO* TimeStampPolicyInfo
)
{
    PAGED_CODE();

    NTSTATUS    Status = STATUS_SUCCESS;
    PVOID       CertDirectory = nullptr;
    KAPC_STATE  SystemContext = { };

    do
    {
        SigningTime->QuadPart = 0;

        CiFreePolicyInfo(PolicyInfo);
        CiFreePolicyInfo(TimeStampPolicyInfo);

        if (HashSize != MINCRYPT_SHA1_LENGTH)
        {
            Status = STATUS_INVALID_IMAGE_HASH;
            break;
        }

        if (SecurityDirectory->Size != 0u &&
            SecurityDirectory->VirtualAddress != 0u)
        {
            CertDirectory = ExAllocatePoolWithTag(PagedPool, SecurityDirectory->Size, 'omed');
            if (CertDirectory == nullptr)
            {
                Status = STATUS_NO_MEMORY;
                break;
            }

            LARGE_INTEGER   Offset = {};
            IO_STATUS_BLOCK IoStatusBlock = {};

            Offset.LowPart = SecurityDirectory->VirtualAddress;

            Status = ZwReadFile(FileHandle, nullptr, nullptr, nullptr, &IoStatusBlock,
                CertDirectory, SecurityDirectory->Size, &Offset, nullptr);
            if (Status == STATUS_PENDING)
            {
                ZwWaitForSingleObject(FileHandle, FALSE, nullptr);

                MemoryBarrier();
                Status = IoStatusBlock.Status;
            }

            if (!NT_SUCCESS(Status))
            {
                break;
            }

            KeStackAttachProcess(PsInitialSystemProcess, &SystemContext);
            {
                Status = CiCheckSignedFile(
                    Hash,
                    HashSize,
                    HashAlgId,
                    CertDirectory,
                    SecurityDirectory->Size,
                    PolicyInfo,
                    SigningTime,
                    TimeStampPolicyInfo);
            }
            KeUnstackDetachProcess(&SystemContext);

            if (NT_SUCCESS(Status))
            {
                break;
            }

            if (Status != STATUS_INVALID_IMAGE_HASH)
            {
                break;
            }
        }

        KeStackAttachProcess(PsInitialSystemProcess, &SystemContext);
        {
            Status = CiVerifyHashInCatalog(
                Hash,
                HashSize,
                HashAlgId,
                FALSE,
                0,
                0x2007F,
                PolicyInfo,
                nullptr,
                SigningTime,
                TimeStampPolicyInfo);
            if (Status == STATUS_INVALID_IMAGE_HASH)
            {
                Status = CiVerifyHashInCatalog(
                    Hash,
                    HashSize,
                    HashAlgId,
                    TRUE,
                    0,
                    0x2007F,
                    PolicyInfo,
                    nullptr,
                    SigningTime,
                    TimeStampPolicyInfo);
            }
        }
        KeUnstackDetachProcess(&SystemContext);

    } while (false);

    if (CertDirectory)
    {
        ExFreePoolWithTag(CertDirectory, 'omed');
    }

    return Status;
}

#if (NTDDI_VERSION >= NTDDI_WIN10)
void ValidateFileUsingFileObject(
    _In_ PFILE_OBJECT FileObject
)
{
    PAGED_CODE();

    LOG("Validating file using CiValidateFileObject...");
    LOG("Will verify - %wZ", &FileObject->FileName);

    NTSTATUS Status = STATUS_SUCCESS;

    UINT8   Hash[MINCRYPT_MAX_HASH_LENGTH] = {};
    UINT32  HashSize = sizeof(Hash);
    ALG_ID  HashAlgId = 0u;

    LARGE_INTEGER        SigningTime = {};
    MINCRYPT_POLICY_INFO PolicyInfo = {};
    MINCRYPT_POLICY_INFO TimeStampPolicyInfo = {};

    do
    {
        Status = CiValidateFileObject(
            FileObject,
            0,
            0,
            &PolicyInfo,
            &TimeStampPolicyInfo,
            &SigningTime,
            Hash,
            &HashSize,
            &HashAlgId
        );

        LOG("CiValidateFileObject returned 0x%08X", Status);

        if (!NT_SUCCESS(Status))
        {
            break;
        }

        PrintPolicyInfo(&PolicyInfo);

    } while (false);

    CiFreePolicyInfo(&PolicyInfo);
    CiFreePolicyInfo(&TimeStampPolicyInfo);
}
#endif // NTDDI_VERSION >= NTDDI_WIN10

void ValidateFileUsingFileName(
    _In_ PCUNICODE_STRING FileName
)
{
    PAGED_CODE();

    LOG("Validating file using CiValidateFileLegacyMode...");
    LOG("Will verify - %wZ", FileName);

    NTSTATUS Status     = STATUS_SUCCESS;
    HANDLE   FileHandle = nullptr;

    do
    {
        OBJECT_ATTRIBUTES ObjectAttributes = { };
        InitializeObjectAttributes(
            &ObjectAttributes,
            const_cast<PUNICODE_STRING>(FileName),
            OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
            nullptr,
            nullptr);

        IO_STATUS_BLOCK IoStatusBlock = { };

        Status = ZwOpenFile(
            &FileHandle,
            SYNCHRONIZE | FILE_READ_DATA, // ACCESS_MASK, we use SYNCHRONIZE because we might need to wait on the handle in order to wait for the file to be read
            &ObjectAttributes,
            &IoStatusBlock,
            FILE_SHARE_READ,
            FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT // FILE_SYNCHRONOUS_IO_NONALERT so that zwReadfile will pend for us until reading is done
        );
        if (!NT_SUCCESS(Status))
        {
            break;
        }

        LARGE_INTEGER    Offset     = {};
        IMAGE_NT_HEADERS NtHeader   = {};
        IMAGE_DOS_HEADER DosHeader  = {};

        Status = ZwReadFile(FileHandle, nullptr, nullptr, nullptr, &IoStatusBlock,
            &DosHeader, sizeof(IMAGE_DOS_HEADER), &Offset, nullptr);
        if (!NT_SUCCESS(Status))
        {
            break;
        }

        // !!!!!
        // By default, all PE files are considered valid.
        // So, not check PE.

        Offset.LowPart = DosHeader.e_lfanew;

        Status = ZwReadFile(FileHandle, nullptr, nullptr, nullptr, &IoStatusBlock,
            &NtHeader, sizeof(IMAGE_NT_HEADERS), &Offset, nullptr);
        if (!NT_SUCCESS(Status))
        {
            break;
        }

        PIMAGE_DATA_DIRECTORY SecurityDirectory = &NtHeader.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY];

        LARGE_INTEGER         SigningTime = {};
        MINCRYPT_POLICY_INFO  PolicyInfo  = {};
        MINCRYPT_POLICY_INFO  TimeStampPolicyInfo = {};

        // digest of notepad++.exe
        UINT8 Hash[MINCRYPT_SHA1_LENGTH] =
        {
            0x83, 0xF6, 0x68, 0x3E, 0x64, 0x9C, 0x70, 0xB9, 0x8D, 0x0B,
            0x5A, 0x8D, 0xBF, 0x9B, 0xD4, 0x70, 0xE6, 0x05, 0xE6, 0xA7
        };

        Status = ValidateFileLegacyMode(
            FileHandle,
            Hash,
            MINCRYPT_SHA1_LENGTH,
            CALG_SHA1,
            SecurityDirectory,
            &PolicyInfo,
            &SigningTime,
            &TimeStampPolicyInfo);
        if (!NT_SUCCESS(Status))
        {
            LOG("Verification failed!");
            break;
        }

#if (NTDDI_VERSION >= NTDDI_WIN10)
        PrintPolicyInfoLegacyMode(&PolicyInfo);
#else
        LOG("Verification succeeded!");
#endif

    } while (false);

    if (FileHandle)
    {
        ZwClose(FileHandle);
    }
}
