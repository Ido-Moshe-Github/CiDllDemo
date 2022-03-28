#pragma once

void ValidateFileUsingFileName(
    _In_ PCUNICODE_STRING FileName
);

#if (NTDDI_VERSION >= NTDDI_WIN10)
void ValidateFileUsingFileObject(
    _In_ PFILE_OBJECT FileObject
);
#endif // NTDDI_VERSION >= NTDDI_WIN10
