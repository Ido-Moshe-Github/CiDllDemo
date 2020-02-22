#include "RAIIUtils.h"
#include "SignatureCheck.h"
#include "ci.h"

#define SHA1_IDENTIFIER 0x8004
#define SHA256_IDENTIFIER 0x800C
#define IMAGE_DIRECTORY_ENTRY_SECURITY  4


extern "C" PVOID RtlImageDirectoryEntryToData(PVOID BaseAddress, BOOLEAN MappedAsImage, USHORT Directory, PULONG Size);
bool inRange(const BYTE* rangeStartAddr, const BYTE* rangeEndAddr, const BYTE* addrToCheck);
void parsePolicyInfo(const pPolicyInfo policyInfo);
bool ciCheckSignedFileWrapper(const LPWIN_CERTIFICATE win_cert, ULONG sizeOfSecurityDirectory);


void validateFileUsingCiCheckSignedFile(PCUNICODE_STRING imageFileName)
{
    KdPrint(("Validating file using CiCheckSignedFile...\n"));

    FileReadHandleGuard fileHandleGuard(imageFileName);
    if (!fileHandleGuard.isValid()) return;

    // create section for the file
    SectionHandleGuard sectionHandleGuard(fileHandleGuard.get());
    if (!sectionHandleGuard.isValid()) return;

    // get section object from section handle
    SectionObjectGuard sectionObjectGuard(sectionHandleGuard.get());
    if (!sectionObjectGuard.isValid()) return;

    // map a view of the section
    SectionViewGuard viewGuard(sectionObjectGuard.get());
    if (!viewGuard.isValid()) return;

    // fetch the security directory
    PVOID securityDirectoryEntry = nullptr;
    ULONG securityDirectoryEntrySize = 0;
    securityDirectoryEntry = RtlImageDirectoryEntryToData(
        viewGuard.getViewBaseAddress(),
        TRUE, // we tell RtlImageDirectoryEntryToData it's mapped as image because then it will treat the RVA as offset from the beginning of the view, which is what we want. See https://doxygen.reactos.org/dc/d30/dll_2win32_2dbghelp_2compat_8c_source.html#l00102
        IMAGE_DIRECTORY_ENTRY_SECURITY,
        &securityDirectoryEntrySize
    );

    if (securityDirectoryEntry == nullptr)
    {
        KdPrint(("no security directory\n"));
        return;
    }

    KdPrint(("securityDirectoryEntry found at: %p, size: %x\n",
        securityDirectoryEntry, securityDirectoryEntrySize));

    // Make sure the security directory is contained in the file view
    const BYTE* endOfFileAddr = static_cast<BYTE*>(viewGuard.getViewBaseAddress()) + viewGuard.getViewSize();
    const BYTE* endOfSecurityDir = static_cast<BYTE*>(securityDirectoryEntry) + securityDirectoryEntrySize;
    if (endOfSecurityDir > endOfFileAddr || securityDirectoryEntry < viewGuard.getViewBaseAddress())
    {
        KdPrint(("security directory is not contained in file view!\n"));
        return;
    }

    // technically, there can be several WIN_CERTIFICATE in a file. This not common, and, for simplicity,
    // we'll assume there's only one
    LPWIN_CERTIFICATE winCert = static_cast<LPWIN_CERTIFICATE>(securityDirectoryEntry);
    KdPrint(("WIN_CERTIFICATE at: %p, revision = %x, type = %x, length = %xd, bCertificate = %p\n",
        securityDirectoryEntry, winCert->wRevision, winCert->wCertificateType, winCert->dwLength, static_cast<PVOID>(winCert->bCertificate)));

    ciCheckSignedFileWrapper(winCert, securityDirectoryEntrySize);
}


bool ciCheckSignedFileWrapper(const LPWIN_CERTIFICATE win_cert, ULONG sizeOfSecurityDirectory)
{
    // prepare the parameters required for calling CiCheckSignedFile
    PolicyInfoGuard signerPolicyInfo;
    PolicyInfoGuard timestampingAuthorityPolicyInfo;
    LARGE_INTEGER signingTime = {};
    const int digestSize = 20; // sha1 len, 0x14
    const int digestIdentifier = 0x8004; // sha1
    const BYTE digestBuffer[] = // digest of notepad++.exe
            { 0x83, 0xF6, 0x68, 0x3E, 0x64, 0x9C, 0x70, 0xB9, 0x8D, 0x0B,
              0x5A, 0x8D, 0xBF, 0x9B, 0xD4, 0x70, 0xE6, 0x05, 0xE6, 0xA7 };

    // CiCheckSignedFile() allocates memory from the paged pool, so make sure we're at IRQL < 2,
    // where access to paged memory is allowed
    NT_ASSERT(KeGetCurrentIrql() < DISPATCH_LEVEL);

    const NTSTATUS status = CiCheckSignedFile(
        (PVOID)digestBuffer,
        digestSize,
        digestIdentifier,
        win_cert,
        (int)sizeOfSecurityDirectory,
        &signerPolicyInfo.get(),
        &signingTime,
        &timestampingAuthorityPolicyInfo.get());
    KdPrint(("CiCheckSignedFile returned 0x%08X\n", status));

    if (NT_SUCCESS(status))
    {
        parsePolicyInfo(&signerPolicyInfo.get());
        return true;
    }

    return false;
}

void validateFileUsingCiValidateFileObject(PFILE_OBJECT fileObject)
{
    KdPrint(("Validating file using CiValidateFileObject...\n"));
    NT_ASSERT(KeGetCurrentIrql() < DISPATCH_LEVEL);

    PolicyInfoGuard signerPolicyInfo;
    PolicyInfoGuard timestampingAuthorityPolicyInfo;
    LARGE_INTEGER signingTime = {};
    int digestSize = 64;
    int digestIdentifier = 0;
    BYTE digestBuffer[64] = {};

    const NTSTATUS status = CiValidateFileObject(
        fileObject,
        0,
        0,
        &signerPolicyInfo.get(),
        &timestampingAuthorityPolicyInfo.get(),
        &signingTime,
        digestBuffer,
        &digestSize,
        &digestIdentifier
    );

    KdPrint(("CiValidateFileObject returned 0x%08X\n", status));
    if (NT_SUCCESS(status))
    {
        parsePolicyInfo(&signerPolicyInfo.get());
        return;
    }
}

void parsePolicyInfo(const pPolicyInfo policyInfo)
{
    if (policyInfo == nullptr)
    {
        KdPrint(("parsePolicyInfo - paramter is null\n"));
        return;
    }

    if (policyInfo->structSize == 0)
    {
        KdPrint(("policy info is empty\n"));
        return;
    }

    if (policyInfo->certChainInfo == nullptr)
    {
        KdPrint(("certChainInfo is null\n"));
        return;
    }

    const pCertChainInfoHeader chainInfoHeader = policyInfo->certChainInfo;

    const BYTE* startOfCertChainInfo = (BYTE*)(chainInfoHeader);
    const BYTE* endOfCertChainInfo = (BYTE*)(policyInfo->certChainInfo) + chainInfoHeader->bufferSize;

    if (!inRange(startOfCertChainInfo, endOfCertChainInfo, (BYTE*)chainInfoHeader->ptrToCertChainMembers))
    {
        KdPrint(("chain members out of range\n"));
        return;
    }

    // need to make sure we have enough room to accomodate the chain member struct
    if (!inRange(startOfCertChainInfo, endOfCertChainInfo, (BYTE*)chainInfoHeader->ptrToCertChainMembers + sizeof(CertChainMember)))
    {
        KdPrint(("chain member out of range\n"));
        return;
    }

    // we are interested in the first certificate in the chain - the signer itself
    pCertChainMember signerChainMember = chainInfoHeader->ptrToCertChainMembers;

    KdPrint(("Signer certificate:\n  digest algorithm - 0x%x\n  size - %zu\n  subject - %.*s\n  issuer - %.*s\n",   \
        signerChainMember->digestIdetifier,                                                                         \
        signerChainMember->certificate.size,                                                                        \
        signerChainMember->subjectName.nameLen,                                                                     \
        static_cast<char*>(signerChainMember->subjectName.pointerToName),                                           \
        signerChainMember->issuerName.nameLen,                                                                      \
        static_cast<char*>(signerChainMember->issuerName.pointerToName))                                            \
    );

    UNREFERENCED_PARAMETER(signerChainMember);
}

bool inRange(const BYTE* rangeStartAddr, const BYTE* rangeEndAddr, const BYTE* addrToCheck)
{
    if (addrToCheck > rangeEndAddr || addrToCheck < rangeStartAddr)
    {
        return false;
    }

    return true;
}
