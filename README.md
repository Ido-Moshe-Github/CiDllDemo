# CiDemoDriver

A joint effort of Liron Zuarets and I, CiDemoDriver is a very simple driver which demonstrates using ci.dll
API in order to validate files. This repository complements a [write-up] we published about the subject.

### Logic

The driver registers a ProcessCreateProcessNotify routine and whenever a new process is created, it tries to verify its
Authentocide signature using two ci.dll APIs:
- CiValidateFileObject: which acts directly on the file object
- CiCheckSignedFile: which requires the caller to provide a file digest. Since file digest calculation is
beyond the scope of this demo, we hard-coded the file digest of Notepad++.exe (this PE is included under "ExecutablesForTesting"
folder) and the function will only succeed for this file.

If the file's signature was verified successfully, the driver will parse the output PolicyInfo structure in order to extract the
signing certificate and its details.

### Requirements

- Supports **Windows 10**. If you want to use earlier OS versions, you need to remove the dependency in CiValidateFileObject
from the code and the lib files, and change the project properties to the appropriate OS.
- Supports **x86**, **x64** architectures
- Can be compiled using Visual Studio 2019. The solution file is included.
- In case you need to link against additional ci.dll functions, refer to the README inside GeneratingLibFiles.
- In order to run the driver, use the .inf file to install and then load the driver by: `sc start CiDemoDriver`

### License

This software is open-source under the MIT license. See the LICENSE.txt file in this repository.

  [write-up]: <https://medium.com/cybereason/code-integrity-in-the-kernel-66b3f5cce5f>