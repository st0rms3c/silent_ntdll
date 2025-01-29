#include <stdio.h>
#include <Windows.h>

EXTERN_C IMAGE_DOS_HEADER __ImageBase;

struct syscall {
    BYTE* addr;
    BYTE name[MAX_PATH];
    DWORD crc32;
    DWORD ssn;
    BOOL sorted;
};

static struct syscall syscalls[512] = { 0 };

DWORD crc32(BYTE* input, size_t bytes)
{
    DWORD crc32 = 0xFFFFFFFF;

    for (size_t i = 0; i < bytes; i++)
    {
        // Convert each character to lowercase prior to XORing.
        crc32 ^= (input[i] >= 0x41 && input[i] <= 0x5A) ? input[i] + 32 : input[i];

        for (size_t j = 0; j < 8; j++)
            crc32 = (crc32 >> 1) ^ ((crc32 & 1) ? 0xEDB88320 : 0);
    }

    return(crc32 ^ 0xFFFFFFFF);
}

int main(int argc, char* argv[])
{
    BYTE* image = (BYTE*)(&__ImageBase);
    IMAGE_DOS_HEADER* dos_header = (IMAGE_DOS_HEADER*)(image);

    printf("Magic value is: %04X\n", dos_header->e_magic);
    printf("Base address is: %016llX\n", (UINT64)image);
    printf("Base address is: %016llX\n", (UINT64)GetModuleHandleA(NULL));

    IMAGE_NT_HEADERS* nt_headers = (IMAGE_NT_HEADERS*)(image + dos_header->e_lfanew);
    UINT64 address = nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
    IMAGE_IMPORT_DESCRIPTOR* imports = (IMAGE_IMPORT_DESCRIPTOR*)(image + address);

    for (; imports->Characteristics != 0; imports++)
    {
        BYTE* name = image + imports->Name;
        size_t len = 0;

        // No calling strlen()!
        for (;; len++)
        {
            if (name[len] == 0)
                break;
        }

        // Find "kernel32.dll".
        if (crc32(name, len) == 0x6AE69F02)
            break;
    }

    IMAGE_THUNK_DATA* import_names = (IMAGE_THUNK_DATA*)(image + imports->OriginalFirstThunk);
    IMAGE_THUNK_DATA* import_addrs = (IMAGE_THUNK_DATA*)(image + imports->FirstThunk);

    // The first two bytes of an import name are its ordinal value.
    printf("KERNEL32 first import name: %s\n", image + import_names->u1.AddressOfData + 2);
    printf("KERNEL32 first import addr: %016llX\n", import_addrs->u1.AddressOfData);
    
    image = (BYTE*)(import_addrs->u1.AddressOfData & ~0xFFFF);

    do {
        dos_header = (IMAGE_DOS_HEADER*)image;

        // Check for XOR-masked IMAGE_DOS_SIGNATURE.
        if ((dos_header->e_magic ^ 0xFFFF) == 0xA5B2)
        {
            nt_headers = (IMAGE_NT_HEADERS*)(image + dos_header->e_lfanew);

            // Check for XOR-masked IMAGE_NT_SIGNATURE.
            if ((nt_headers->Signature ^ 0xFFFF) == 0xBAAF)
                break;
        }

        image -= 0x10000;

    } while (image > 0);

    printf("KERNEL32 base address: %016llX\n", (UINT64)image);
    printf("KERNEL32 base address: %016llX\n", (UINT64)GetModuleHandleA("kernel32.dll"));

    address = nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
    imports = (IMAGE_IMPORT_DESCRIPTOR*)(image + address);

    for (; imports->Characteristics != 0; imports++)
    {
        BYTE* name = image + imports->Name;
        size_t len = 0;

        // No calling strlen()!
        for (;; len++)
        {
            if (name[len] == 0)
                break;
        }

        // Find "ntdll.dll".
        if (crc32(name, len) == 0x84C05E40)
            break;
    }

    import_names = (IMAGE_THUNK_DATA*)(image + imports->OriginalFirstThunk);
    import_addrs = (IMAGE_THUNK_DATA*)(image + imports->FirstThunk);

    // The first two bytes of an import name are its ordinal value.
    printf("NTDLL first import name: %s\n", image + import_names->u1.AddressOfData + 2);
    printf("NTDLL first import addr: %016llX\n", import_addrs->u1.AddressOfData);

    image = (BYTE*)(import_addrs->u1.AddressOfData & ~0xFFFF);

    do {
        dos_header = (IMAGE_DOS_HEADER*)image;

        // Check for XOR-masked IMAGE_DOS_SIGNATURE.
        if ((dos_header->e_magic ^ 0xFFFF) == 0xA5B2)
        {
            nt_headers = (IMAGE_NT_HEADERS*)(image + dos_header->e_lfanew);

            // Check for XOR-masked IMAGE_NT_SIGNATURE.
            if ((nt_headers->Signature ^ 0xFFFF) == 0xBAAF)
                break;
        }

        image -= 0x10000;

    } while (image > 0);

    printf("NTDLL base address: %016llX\n", (UINT64)image);
    printf("NTDLL base address: %016llX\n", (UINT64)GetModuleHandleA("ntdll.dll"));

    DWORD index = 0;

    address = nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    IMAGE_EXPORT_DIRECTORY* exports = (IMAGE_EXPORT_DIRECTORY*)(image + address);

    UINT32* export_funcs = (UINT32*)(image + exports->AddressOfFunctions);
    UINT32* export_names = (UINT32*)(image + exports->AddressOfNames);
    UINT16* export_nords = (UINT16*)(image + exports->AddressOfNameOrdinals);

    for (DWORD i = 0; i < exports->NumberOfNames; i++)
    {
        BYTE* func_name = (BYTE*)(image + export_names[i]);
        BYTE* func_addr = (BYTE*)(image + export_funcs[export_nords[i]]);

        // Look for exports starting with "Zw" (XOR-masked).
        if ((*((UINT16*)func_name) ^ 0xFFFF) != 0x88A5)
            continue;

        size_t len = 0;

        // No calling strlen() or memcpy()!
        for (;; len++)
        {
            if (func_name[len] == 0)
                break;

            syscalls[index].name[len] = func_name[len];
        }

        // Convert "Zw" to "Nt" for checksum/lookup purposes.
        syscalls[index].name[0] ^= 0x14;
        syscalls[index].name[1] ^= 0x03;

        syscalls[index].addr = func_addr;
        syscalls[index].crc32 = crc32(syscalls[index].name, len);

        index++;
    }

    DWORD ssn = 0;

    for (;;)
    {
        BOOL found = FALSE;
        BYTE* lowest_addr = NULL;
        DWORD lowest_index = 0;

        for (DWORD i = 0; i < index; i++)
        {
            if (syscalls[i].sorted == TRUE)
                continue;

            // Find the "unsorted" entry with the lowest address.
            if (lowest_addr == NULL || syscalls[i].addr < lowest_addr)
            {
                found = TRUE;
                lowest_addr = syscalls[i].addr;
                lowest_index = i;
            }
        }

        // No more entries.
        if (found == FALSE)
            break;
        
        syscalls[lowest_index].ssn = ssn++;
        syscalls[lowest_index].sorted = TRUE;

        printf("SYSCALL %s SSN: %04X\n", syscalls[lowest_index].name, syscalls[lowest_index].ssn);
    }

    return(0);
}
