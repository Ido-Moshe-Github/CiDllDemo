# Generating import libraries (.lib files)

Usually when linking with a certain dll, you’d use an import library provided by the vendor. 
In our case, no such ci.lib file is provided and we need to generate it ourselves.
This lib file should be added as a linker input in the project properties.

## 64 bit

Get the exported functions from the dll, using dumpbin utility: 

`dumpbin /EXPORTS c:\windows\system32\ci.dll`

Create a .def file. It will looks something like this:

```c
LIBRARY ci.dll
EXPORTS
CiCheckSignedFile
CiFreePolicyInfo
CiValidateFileObject
```

Generate the .lib file using the lib utility:

`lib /def:ci.def /machine:x64 /out:ci.lib`


## 32 bit

Here the situation gets a bit trickier, since in 32bit the functions are decorated to
include the sum of the arguments (in bytes), for example:

`CiFreePolicyInfo@4`

But ci.dll is exporting the functions in their non-decorated shape, so we need to create a .lib file that makes this translation.

- Follow the first two steps of the 64bit section above.

- Create a C++ file with function stubs - the same signature but dummy body. You basically mimic what the vendor did when exporting
  the functions from their code. For example:
  
```c
extern "C" __declspec(dllexport) PVOID _stdcall CiFreePolicyInfo(PVOID policyInfoPtr)
{
    PVOID dummyReturnValue = nullptr;
    return dummyReturnValue;
}
```

An example of such file is included in this repo under the name CiStubs.cpp.

- Compile it into an OBJ file.

- Generate the .lib file using the lib utility, this time with the OBJ file:

`lib /def:ci.def /machine:x86 /out:ci.lib <obj file>`
