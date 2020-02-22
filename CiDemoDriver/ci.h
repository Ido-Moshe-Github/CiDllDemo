#pragma once

#include <wdm.h>
#include <minwindef.h>


/**
*  This struct was copied from <wintrust.h> and encapsulates a signature used in verifying executable files.
*/
typedef struct _WIN_CERTIFICATE {
    DWORD dwLength;                         // Specifies the length, in bytes, of the signature
    WORD  wRevision;                        // Specifies the certificate revision
    WORD  wCertificateType;                 // Specifies the type of certificate
    BYTE  bCertificate[ANYSIZE_ARRAY];      // An array of certificates
} WIN_CERTIFICATE, * LPWIN_CERTIFICATE;


/**
*  Describes the location (address) and size of a ASN.1 blob within a buffer.
*
*  @note  The data itself is not contained in the struct.
*/
typedef struct _Asn1BlobPtr
{
    int size;               // size of the ASN.1 blob
    PVOID ptrToData;        // where the ASN.1 blob starts
} Asn1BlobPtr, * pAsn1BlobPtr;


/**
*  Describes the location (address) and size of a certificate subject/issuer name, within a buffer.
*
*  @note  The data itself (name) is not contained in the struct.
*
*  @note  the reason for separating these fields into their own struct was to match the padding we
*         observed in CertChainMember struct after the second 'short' field - once you enclose it 
*         into a struct, on x64 bit machines there will be a padding of 4 bytes at the end of the struct,
*         because the largest member of the struct is of size 8 and it dictates the alignment of the struct.
*/
typedef struct _CertificatePartyName
{
    PVOID pointerToName;
    short nameLen;
    short unknown;
} CertificatePartyName, * pCertificatePartyName;


/**
*  Contains various data about a specific certificate in the chain and also points to the actual certificate.
*
*  @note  the digest described in this struct is the digest that was used to create the certificate - not for
*         signing the file.
*
*  @note  The size reserved for digest is 64 byte regardless of the digest type, in order to accomodate SHA2/3's
*         max size of 512bit. The memory is not zeroed, so we must take the actual digestSize into account when
*         reading it.
*/
typedef struct _CertChainMember
{
    int digestIdetifier;                // e.g. 0x800c for SHA256
    int digestSize;                     // e.g. 0x20 for SHA256
    BYTE digestBuffer[64];              // contains the digest itself, where the digest size is dictated by digestSize

    CertificatePartyName subjectName;   // pointer to the subject name
    CertificatePartyName issuerName;    // pointer to the issuer name

    Asn1BlobPtr certificate;            // ptr to actual cert in ASN.1 - including the public key
} CertChainMember, * pCertChainMember;


/**
*  Describes the format of certChainInfo buffer member of PolicyInfo struct. This header maps the types,
*  locations, and quantities of the data which is contained in the buffer.
*
*  @note  when using this struct make sure to check its size first (bufferSize) because it's not guaranteed
*         that all the fields below will exist.
*/
typedef struct _CertChainInfoHeader
{
    // The size of the dynamically allocated buffer
    int bufferSize;

    // points to the start of a series of Asn1Blobs which contain the public keys of the certificates in the chain
    pAsn1BlobPtr ptrToPublicKeys;
    int numberOfPublicKeys;
    
    // points to the start of a series of Asn1Blobs which contain the EKUs
    pAsn1BlobPtr ptrToEkus;
    int numberOfEkus;

    // points to the start of a series of CertChainMembers
    pCertChainMember ptrToCertChainMembers;
    int numberOfCertChainMembers;

    int unknown;

    // ASN.1 blob of authenticated attributes - spcSpOpusInfo, contentType, etc.
    Asn1BlobPtr variousAuthenticodeAttributes;
} CertChainInfoHeader, * pCertChainInfoHeader;


/**
*  Contains information regarding the certificates that were used for signing/timestamping
*
*  @note  you must check structSize before accessing the other members, since some members were added later.
*
*  @note  all structs members, including the length, are populated by ci functions - no need
*         to fill them in adavnce.
*/
typedef struct _PolicyInfo
{
    int structSize;
    NTSTATUS verificationStatus;
    int flags;
    pCertChainInfoHeader certChainInfo; // if not null - contains info about certificate chain
    FILETIME revocationTime;            // when was the certificate revoked (if applicable)
    FILETIME notBeforeTime;             // the certificate is not valid before this time
    FILETIME notAfterTime;              // the certificate is not valid before this time
} PolicyInfo, *pPolicyInfo;


/**
*  Given a file digest and signature of a file, verify the signature and provide information regarding
*  the certificates that was used for signing (the entire certificate chain)
*
*  @note  the function allocates a buffer from the paged pool --> can be used only where IRQL < DISPATCH_LEVEL
*
*  @param  digestBuffer - buffer containing the digest
*
*  @param  digestSize - size of the digest, e.g. 0x20 for SHA256, 0x14 for SHA1
*
*  @param  digestIdentifier - digest algorithm identifier, e.g. 0x800c for SHA256, 0x8004 for SHA1
*
*  @param  winCert - pointer to the start of the security directory
*
*  @param  sizeOfSecurityDirectory - size the security directory
*
*  @param  policyInfoForSigner[out] - PolicyInfo containing information about the signer certificate chain
*
*  @param  signingTime[out] - when the file was signed (FILETIME format)
*
*  @param  policyInfoForTimestampingAuthority[out] - PolicyInfo containing information about the timestamping 
*          authority (TSA) certificate chain
*
*  @return  0 if the file digest in the signature matches the given digest and the signer cetificate is verified.
*           Various error values otherwise, for example:
*           STATUS_INVALID_IMAGE_HASH - the digest does not match the digest in the signature
*           STATUS_IMAGE_CERT_REVOKED - the certificate used for signing the file is revoked
*           STATUS_IMAGE_CERT_EXPIRED - the certificate used for signing the file has expired
*/
extern "C" __declspec(dllimport) NTSTATUS _stdcall CiCheckSignedFile(
    const PVOID digestBuffer,
    int digestSize,
    int digestIdentifier,
    const LPWIN_CERTIFICATE winCert,
    int sizeOfSecurityDirectory,
    PolicyInfo* policyInfoForSigner,
    LARGE_INTEGER* signingTime,
    PolicyInfo* policyInfoForTimestampingAuthority);


/**
*  Resets a PolicyInfo struct - frees the dynamically allocated buffer in PolicyInfo (certChainInfo) if not null.
*  Zeros the entire PolicyInfo struct.
*
*  @param  policyInfo - the struct to reset.
*
*  @return  the struct which was reset.
*/
extern "C" __declspec(dllimport) PVOID _stdcall CiFreePolicyInfo(PolicyInfo* policyInfo);


/**
*  Given a file object, verify the signature and provide information regarding
*  the certificates that was used for signing (the entire certificate chain)
*
*  @note  the function allocates memory from the paged pool --> can be used only where IRQL < DISPATCH_LEVEL
*
*  @param  fileObject[in] - fileObject of the PE in question
*
*  @param  a2[in] - unknown, needs to be reversed. 0 is a valid value.
*
*  @param  a3[in] - unknown, needs to be reversed. 0 is a valid value.
*
*  @param  policyInfoForSigner[out] - PolicyInfo containing information about the signer certificate chain
*
*  @param  signingTime[out] - when the file was signed
*
*  @param  policyInfoForTimestampingAuthority[out] - PolicyInfo containing information about the timestamping
*          authority (TSA) certificate chain
*
*  @param  digestBuffer[out] - buffer to be filled with the digest, must be at least 64 bytes
*
*  @param  digestSize[inout] - size of the digest. Must be at leat 64 and will be changed by the function to 
*                              reflect the actual digest length.
*
*  @param  digestIdentifier[out] - digest algorithm identifier, e.g. 0x800c for SHA256, 0x8004 for SHA1
*
*  @return  0 if the file digest in the signature matches the given digest and the signer cetificate is verified.
*           Various error values otherwise, for example:
*           STATUS_INVALID_IMAGE_HASH - the digest does not match the digest in the signature
*           STATUS_IMAGE_CERT_REVOKED - the certificate used for signing the file is revoked
*           STATUS_IMAGE_CERT_EXPIRED - the certificate used for signing the file has expired
*/
extern "C" __declspec(dllimport) NTSTATUS _stdcall CiValidateFileObject(
    struct _FILE_OBJECT* fileObject,
    int a2,
    int a3,
    PolicyInfo* policyInfoForSigner,
    PolicyInfo* policyInfoForTimestampingAuthority,
    LARGE_INTEGER* signingTime,
    BYTE* digestBuffer,
    int* digestSize,
    int* digestIdentifier
);