/*
Cuckoo Sandbox - Automated Malware Analysis
Copyright (C) 2010-2014 Cuckoo Sandbox Developers

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include <stdio.h>
#include <windows.h>
#include <ctype.h>
#include <shlwapi.h>
#include "ntapi.h"
#include "misc.h"
#include "config.h"

ULONG_PTR parent_process_id() // By Napalm @ NetCore2K (rohitab.com)
{
    ULONG_PTR pbi[6]; ULONG ulSize = 0;
    LONG (WINAPI *NtQueryInformationProcess)(HANDLE ProcessHandle,
        ULONG ProcessInformationClass, PVOID ProcessInformation,
        ULONG ProcessInformationLength, PULONG ReturnLength);

    *(FARPROC *) &NtQueryInformationProcess = GetProcAddress(
        GetModuleHandle("ntdll"), "NtQueryInformationProcess");

    if(NtQueryInformationProcess != NULL && NtQueryInformationProcess(
            GetCurrentProcess(), 0, &pbi, sizeof(pbi), &ulSize) >= 0 &&
            ulSize == sizeof(pbi)) {
        return pbi[5];
    }
    return 0;
}

DWORD pid_from_process_handle(HANDLE process_handle)
{
    PROCESS_BASIC_INFORMATION pbi = {}; ULONG ulSize;
    LONG (WINAPI *NtQueryInformationProcess)(HANDLE ProcessHandle,
        ULONG ProcessInformationClass, PVOID ProcessInformation,
        ULONG ProcessInformationLength, PULONG ReturnLength);

    *(FARPROC *) &NtQueryInformationProcess = GetProcAddress(
        GetModuleHandle("ntdll"), "NtQueryInformationProcess");

    if(NtQueryInformationProcess != NULL && NtQueryInformationProcess(
            process_handle, 0, &pbi, sizeof(pbi), &ulSize) >= 0 &&
            ulSize == sizeof(pbi)) {
        return pbi.UniqueProcessId;
    }
    return 0;
}

DWORD pid_from_thread_handle(HANDLE thread_handle)
{
    THREAD_BASIC_INFORMATION tbi = {}; ULONG ulSize;
    LONG (WINAPI *NtQueryInformationThread)(HANDLE ThreadHandle,
        ULONG ThreadInformationClass, PVOID ThreadInformation,
        ULONG ThreadInformationLength, PULONG ReturnLength);

    *(FARPROC *) &NtQueryInformationThread = GetProcAddress(
        GetModuleHandle("ntdll"), "NtQueryInformationThread");

    if(NtQueryInformationThread != NULL && NtQueryInformationThread(
            thread_handle, 0, &tbi, sizeof(tbi), &ulSize) >= 0 &&
            ulSize == sizeof(tbi)) {
        return (DWORD) tbi.ClientId.UniqueProcess;
    }
    return 0;
}

DWORD random()
{
    static BOOLEAN (WINAPI *pRtlGenRandom)(PVOID RandomBuffer,
        ULONG RandomBufferLength);

    if(pRtlGenRandom == NULL) {
        *(FARPROC *) &pRtlGenRandom = GetProcAddress(
            GetModuleHandle("advapi32"), "SystemFunction036");
    }

    DWORD ret;
    return pRtlGenRandom(&ret, sizeof(ret)) ? ret : rand();
}

DWORD randint(DWORD min, DWORD max)
{
    return min + (random() % (max - min + 1));
}

BOOL is_directory_objattr(const OBJECT_ATTRIBUTES *obj)
{
    static NTSTATUS (WINAPI *pNtQueryAttributesFile)(
        _In_   const OBJECT_ATTRIBUTES *ObjectAttributes,
        _Out_  PFILE_BASIC_INFORMATION FileInformation
    );

    if(pNtQueryAttributesFile == NULL) {
        *(FARPROC *) &pNtQueryAttributesFile = GetProcAddress(
            GetModuleHandle("ntdll"), "NtQueryAttributesFile");
    }

    FILE_BASIC_INFORMATION basic_information;
    if(NT_SUCCESS(pNtQueryAttributesFile(obj, &basic_information))) {
        return basic_information.FileAttributes & FILE_ATTRIBUTE_DIRECTORY;
    }
    return FALSE;
}

// hide our module from PEB
// http://www.openrce.org/blog/view/844/How_to_hide_dll

#define CUT_LIST(item) \
    item.Blink->Flink = item.Flink; \
    item.Flink->Blink = item.Blink

void hide_module_from_peb(HMODULE module_handle)
{
    LDR_MODULE *mod; PEB *peb = (PEB *) readfsdword(0x30);

    for (mod = (LDR_MODULE *) peb->LoaderData->InLoadOrderModuleList.Flink;
         mod->BaseAddress != NULL;
         mod = (LDR_MODULE *) mod->InLoadOrderModuleList.Flink) {

        if(mod->BaseAddress == module_handle) {
            CUT_LIST(mod->InLoadOrderModuleList);
            CUT_LIST(mod->InInitializationOrderModuleList);
            CUT_LIST(mod->InMemoryOrderModuleList);

            // TODO test whether this list is really used as a linked list
            // like InLoadOrderModuleList etc
            CUT_LIST(mod->HashTableEntry);

            memset(mod, 0, sizeof(LDR_MODULE));
            break;
        }
    }
}

uint32_t path_from_handle(HANDLE handle,
    wchar_t *path, uint32_t path_buffer_len)
{
    static NTSTATUS (WINAPI *pNtQueryVolumeInformationFile)(
        _In_   HANDLE FileHandle,
        _Out_  PIO_STATUS_BLOCK IoStatusBlock,
        _Out_  PVOID FsInformation,
        _In_   ULONG Length,
        _In_   FS_INFORMATION_CLASS FsInformationClass
    );

    if(pNtQueryVolumeInformationFile == NULL) {
        *(FARPROC *) &pNtQueryVolumeInformationFile = GetProcAddress(
            GetModuleHandle("ntdll"), "NtQueryVolumeInformationFile");
    }

    static NTSTATUS (WINAPI *pNtQueryInformationFile)(
        _In_   HANDLE FileHandle,
        _Out_  PIO_STATUS_BLOCK IoStatusBlock,
        _Out_  PVOID FileInformation,
        _In_   ULONG Length,
        _In_   FILE_INFORMATION_CLASS FileInformationClass
    );

    if(pNtQueryInformationFile == NULL) {
        *(FARPROC *) &pNtQueryInformationFile = GetProcAddress(
            GetModuleHandle("ntdll"), "NtQueryInformationFile");
    }

    IO_STATUS_BLOCK status = {};
    FILE_FS_VOLUME_INFORMATION volume_information;

    unsigned char buf[FILE_NAME_INFORMATION_REQUIRED_SIZE];
    FILE_NAME_INFORMATION *name_information = (FILE_NAME_INFORMATION *) buf;

    // get the volume serial number of the directory handle
    if(NT_SUCCESS(pNtQueryVolumeInformationFile(handle, &status,
            &volume_information, sizeof(volume_information),
            FileFsVolumeInformation)) == 0) {
        return 0;
    }

    unsigned long serial_number;

    // enumerate all harddisks in order to find the
    // corresponding serial number
    wcscpy(path, L"?:\\");
    for (path[0] = 'A'; path[0] <= 'Z'; path[0]++) {
        if(GetVolumeInformationW(path, NULL, 0, &serial_number, NULL,
                NULL, NULL, 0) == 0 ||
                serial_number != volume_information.VolumeSerialNumber) {
            continue;
        }

        // obtain the relative path for this filename on the given harddisk
        if(NT_SUCCESS(pNtQueryInformationFile(handle, &status,
                name_information, FILE_NAME_INFORMATION_REQUIRED_SIZE,
                FileNameInformation))) {

            uint32_t length =
                name_information->FileNameLength / sizeof(wchar_t);

            // NtQueryInformationFile omits the "C:" part in a
            // filename, apparently
            wcsncpy(path + 2, name_information->FileName,
                path_buffer_len - 2);

            return length + 2 < path_buffer_len ?
                length + 2 : path_buffer_len - 1;
        }
    }
    return 0;
}

uint32_t path_from_object_attributes(const OBJECT_ATTRIBUTES *obj,
    wchar_t *path, uint32_t buffer_length)
{
    if(obj->ObjectName == NULL || obj->ObjectName->Buffer == NULL) {
        return 0;
    }

    // ObjectName->Length is actually the size in bytes.
    uint32_t obj_length = obj->ObjectName->Length / sizeof(wchar_t);

    if(obj->RootDirectory == NULL) {
        wcsncpy(path, obj->ObjectName->Buffer, buffer_length);
        return obj_length > buffer_length ? buffer_length : obj_length;
    }

    uint32_t length = path_from_handle(obj->RootDirectory,
        path, buffer_length);

    path[length++] = L'\\';
    wcsncpy(&path[length], obj->ObjectName->Buffer, buffer_length - length);

    length += obj_length;
    return length > buffer_length ? buffer_length : length;
}

int ensure_absolute_path(wchar_t *out, const wchar_t *in, int length)
{
    if(!wcsncmp(in, L"\\??\\", 4)) {
        length -= 4, in += 4;
        wcsncpy(out, in, length < MAX_PATH ? length : MAX_PATH);
        return out[length] = 0, length;
    }
    else if(in[1] != ':' || (in[2] != '\\' && in[2] != '/')) {
        wchar_t cur_dir[MAX_PATH], fname[MAX_PATH];
        GetCurrentDirectoryW(ARRAYSIZE(cur_dir), cur_dir);

        // ensure the filename is zero-terminated
        wcsncpy(fname, in, length < MAX_PATH ? length : MAX_PATH);
        fname[length] = 0;

        PathCombineW(out, cur_dir, fname);
        return lstrlenW(out);
    }
    else {
        wcsncpy(out, in, length < MAX_PATH ? length : MAX_PATH);
        return out[length] = 0, length;
    }
}

int is_shutting_down()
{
    HANDLE mutex_handle =
        OpenMutex(SYNCHRONIZE, FALSE, g_config.shutdown_mutex);
    if(mutex_handle != NULL) {
        CloseHandle(mutex_handle);
        return 1;
    }
    return 0;
}
