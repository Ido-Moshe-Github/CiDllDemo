#pragma once

#include <wdm.h>


void validateFileUsingCiValidateFileObject(PFILE_OBJECT FileObject);
void validateFileUsingCiCheckSignedFile(PCUNICODE_STRING imageFileName);
