#pragma once

#include <ntddk.h>
#include <wdm.h>
#include "ci.h"


/**
 *  create a file handle for read.
 *  release handle when exiting the current context.
 */
class FileReadHandleGuard
{
public:
    FileReadHandleGuard(PCUNICODE_STRING imageFileName): _handle(nullptr), _isValid(false)
    {
        IO_STATUS_BLOCK ioStatusBlock = { 0 };
        OBJECT_ATTRIBUTES  objAttr = { 0 };
        InitializeObjectAttributes(
            &objAttr,
            const_cast<PUNICODE_STRING>(imageFileName),
            OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
            nullptr,
            nullptr);

        const NTSTATUS openFileRet = ZwOpenFile(
            &_handle,
            SYNCHRONIZE | FILE_READ_DATA, // ACCESS_MASK, we use SYNCHRONIZE because we might need to wait on the handle in order to wait for the file to be read
            &objAttr,
            &ioStatusBlock,
            FILE_SHARE_READ,
            FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT // FILE_SYNCHRONOUS_IO_NONALERT so that zwReadfile will pend for us until reading is done
        );

        if (!NT_SUCCESS(openFileRet))
        {
            KdPrint(("failed to open file - openFileRet = %d\n", openFileRet));
            return;
        }

        if (ioStatusBlock.Status != STATUS_SUCCESS || _handle == nullptr)
        {
            KdPrint(("ioStatusBlock.Status != STATUS_SUCCESS, or _handle is null\n"));
            return;
        }

        _isValid = true;
    }

    ~FileReadHandleGuard()
    {
        if (_handle != nullptr)
        {
            ZwClose(_handle);
        }
    }

    HANDLE& get() { return _handle; }
    bool isValid() const { return _isValid; }

private:
    HANDLE _handle;
    bool _isValid;
};


/**
 *  create a section handle.
 *  release handle when exiting the current context.
 */
class SectionHandleGuard
{
public:
    SectionHandleGuard(HANDLE& fileHandle) : _handle(nullptr), _isValid(false)
    {
        OBJECT_ATTRIBUTES objectAttributes = { 0 };
        InitializeObjectAttributes(
            &objectAttributes,
            nullptr,
            OBJ_KERNEL_HANDLE, // to make sure user mode cannot access this handle
            nullptr,
            nullptr);

        const NTSTATUS createSectionRet = ZwCreateSection(
            &_handle,
            SECTION_MAP_READ,
            &objectAttributes,
            nullptr, // maximum size - use the file size, in order to map the entire file
            PAGE_READONLY,
            SEC_COMMIT, // map as commit and not as SEC_IMAGE, because SEC_IMAGE will not map things which are not needed for the PE - such as resources and certificates
            fileHandle
        );

        if (!NT_SUCCESS(createSectionRet))
        {
            KdPrint(("failed to create section - ZwCreateSection returned %x\n", createSectionRet));
            return;
        }

        _isValid = true;
    }

    ~SectionHandleGuard()
    {
        if (_handle != nullptr)
        {
            ZwClose(_handle);
        }
    }

    HANDLE& get() { return _handle; }
    bool isValid() const { return _isValid; }

private:
    HANDLE _handle;
    bool _isValid;
};


/**
 *  retrieve a section object from a section handle.
 *  release object reference when exiting the current context.
 */
class SectionObjectGuard
{
public:
    SectionObjectGuard(HANDLE& sectionHandle) : _object(nullptr), _isValid(false)
    {
        const NTSTATUS ret = ObReferenceObjectByHandle(
            sectionHandle,
            SECTION_MAP_READ,
            nullptr,
            KernelMode,
            &_object,
            nullptr
        );

        if (!NT_SUCCESS(ret))
        {
            KdPrint(("ObReferenceObjectByHandle failed -  returned %x\n", ret));
            return;
        }

        _isValid = true;
    }

    ~SectionObjectGuard()
    {
        if (_object != nullptr)
        {
            ObfDereferenceObject(_object);
        }
    }

    PVOID& get() { return _object; }
    bool isValid() const { return _isValid; }

private:
    PVOID _object;
    bool _isValid;
};


/**
 *  create a view of file.
 *  unmap the view when exiting the current context.
 */
class SectionViewGuard
{
public:
    SectionViewGuard(PVOID sectionObject) : _baseAddrOfView(nullptr), _viewSize(0), _isValid(false)
    {
        const NTSTATUS ret = MmMapViewInSystemSpace(
            sectionObject,
            &_baseAddrOfView,
            &_viewSize
        );

        if (!NT_SUCCESS(ret))
        {
            KdPrint(("MmMapViewInSystemSpace failed -  returned %x\n", ret));
            return;
        }

        _isValid = true;
    }

    ~SectionViewGuard()
    {
        if (_baseAddrOfView != nullptr)
        {
            MmUnmapViewInSystemSpace(_baseAddrOfView);
        }
    }

    PVOID getViewBaseAddress() const { return _baseAddrOfView; }
    SIZE_T getViewSize() const { return _viewSize; }
    bool isValid() const { return _isValid; }

private:
    PVOID _baseAddrOfView;
    SIZE_T _viewSize;
    bool _isValid;
};


/**
 *  create a PoicyInfo struct.
 *  Release the memory used by the struct when exiting the current context.
 */
class PolicyInfoGuard
{
public:
    PolicyInfoGuard() : _policyInfo{} {} 

    ~PolicyInfoGuard()
    {
        // CiFreePolicyInfo checks internally if there's memory to free
        CiFreePolicyInfo(&_policyInfo);
    }

    PolicyInfo& get() { return _policyInfo; }

private:
    PolicyInfo _policyInfo;
};