#include <windows.h>
#include <stdio.h>

typedef struct BASE_RELOCATION_BLOCK {
    DWORD PageAddress;
    DWORD BlockSize;
} BASE_RELOCATION_BLOCK, *PBASE_RELOCATION_BLOCK;

typedef struct BASE_RELOCATION_ENTRY {
    USHORT Offset : 12;
    USHORT Type : 4;
} BASE_RELOCATION_ENTRY, *PBASE_RELOCATION_ENTRY;

typedef BOOL (WINAPI *DLLEntry)(HINSTANCE dll, DWORD reason, LPVOID reserved);

int main() {
   
    HANDLE dll = CreateFileA("\\??\\C:\\Temp\\dll_poc.dll", GENERIC_READ, 0, NULL, OPEN_EXISTING, 0, NULL);
    DWORD64 dll_size = GetFileSize(dll, NULL);
    LPVOID dll_bytes = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dll_size);
    DWORD out_size = 0;
    ReadFile(dll, dll_bytes, dll_size, &out_size, NULL);

    PIMAGE_DOS_HEADER dosHeaders = (PIMAGE_DOS_HEADER)dll_bytes;
    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((DWORD_PTR)dll_bytes + dosHeaders->e_lfanew);
    SIZE_T dllImageSize = ntHeaders->OptionalHeader.SizeOfImage;

    LPVOID dll_base = VirtualAlloc((LPVOID)ntHeaders->OptionalHeader.ImageBase, dllImageSize, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    DWORD_PTR deltaImageBase = (DWORD_PTR)dll_base - (DWORD_PTR)ntHeaders->OptionalHeader.ImageBase;
    memcpy(dll_base, dll_bytes, ntHeaders->OptionalHeader.SizeOfHeaders);

    PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(ntHeaders);
    for (size_t i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++) {
        LPVOID sectionDestination = (LPVOID)((DWORD_PTR)dll_base + (DWORD_PTR)section->VirtualAddress);
        LPVOID sectionBytes = (LPVOID)((DWORD_PTR)dll_bytes + (DWORD_PTR)section->PointerToRawData);
        memcpy(sectionDestination, sectionBytes, section->SizeOfRawData);
        section++;
    }

    IMAGE_DATA_DIRECTORY relocations = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
    DWORD_PTR relocationTable = relocations.VirtualAddress + (DWORD_PTR)dll_base;
    DWORD relocationsProcessed = 0;

    while (relocationsProcessed < relocations.Size) {
        PBASE_RELOCATION_BLOCK relocationBlock = (PBASE_RELOCATION_BLOCK)(relocationTable + relocationsProcessed);
        relocationsProcessed += sizeof(BASE_RELOCATION_BLOCK);
        DWORD relocationsCount = (relocationBlock->BlockSize - sizeof(BASE_RELOCATION_BLOCK)) / sizeof(BASE_RELOCATION_ENTRY);
        PBASE_RELOCATION_ENTRY relocationEntries = (PBASE_RELOCATION_ENTRY)(relocationTable + relocationsProcessed);

        for (DWORD i = 0; i < relocationsCount; i++) {
            relocationsProcessed += sizeof(BASE_RELOCATION_ENTRY);

            if (relocationEntries[i].Type == 0) {
                continue;
            }

            DWORD_PTR relocationRVA = relocationBlock->PageAddress + relocationEntries[i].Offset;
            DWORD_PTR addressToPatch = 0;
            ReadProcessMemory(GetCurrentProcess(), (LPCVOID)((DWORD_PTR)dll_base + relocationRVA), &addressToPatch, sizeof(DWORD_PTR), NULL);
            addressToPatch += deltaImageBase;
            memcpy((PVOID)((DWORD_PTR)dll_base + relocationRVA), &addressToPatch, sizeof(DWORD_PTR));
        }
    }

    PIMAGE_IMPORT_DESCRIPTOR importDescriptor = NULL;
    IMAGE_DATA_DIRECTORY importsDirectory = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    importDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)(importsDirectory.VirtualAddress + (DWORD_PTR)dll_base);
    PCHAR libraryName = "";
    HMODULE library = NULL;

    while (importDescriptor->Name != 0) {
        libraryName = (PCHAR)importDescriptor->Name + (DWORD_PTR)dll_base;
        library = LoadLibraryA(libraryName);

        if (library) {
            PIMAGE_THUNK_DATA thunk = NULL;
            thunk = (PIMAGE_THUNK_DATA)((DWORD_PTR)dll_base + importDescriptor->FirstThunk);

            while (thunk->u1.AddressOfData != 0) {
                if (IMAGE_SNAP_BY_ORDINAL(thunk->u1.Ordinal)) {
                    LPCSTR functionOrdinal = (LPCSTR)IMAGE_ORDINAL(thunk->u1.Ordinal);
                    thunk->u1.Function = (DWORD_PTR)GetProcAddress(library, functionOrdinal);
                }
                else {
                    PIMAGE_IMPORT_BY_NAME functionName = (PIMAGE_IMPORT_BY_NAME)((DWORD_PTR)dll_base + thunk->u1.AddressOfData);
                    DWORD_PTR functionAddress = (DWORD_PTR)GetProcAddress(library, functionName->Name);
                    thunk->u1.Function = functionAddress;
                }
                ++thunk;
            }
        }
        importDescriptor++;
    }

    DLLEntry DllEntry = (DLLEntry)((DWORD_PTR)dll_base + ntHeaders->OptionalHeader.AddressOfEntryPoint);
    (*DllEntry)((HINSTANCE)dll_base, DLL_PROCESS_ATTACH, 0);

    CloseHandle(dll);
    HeapFree(GetProcessHeap(), 0, dll_bytes);

    return 0;

}
view raw
