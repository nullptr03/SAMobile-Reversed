#include <cstdio>
#include <cstdlib>
#include <unistd.h>
#include <sys/mman.h>
#include <dlfcn.h>
#include "armhook.h"
#include "../main.h"

#define TRAMPOLINE_SIZE 1024

/*
	push {r0}
	push {r0}
	ldr r0, [pc, #4]
	str r0, [sp, #4]
	pop {r0, pc}
	nop
	db(4)
*/
#define JUMP_CODE "\x01\xB4\x01\xB4\x01\x48\x01\x90\x01\xBD\x00\xBF\x00\x00\x00\x00"
constexpr auto JUMP_CODE_SIZE = sizeof(JUMP_CODE) - 1;

ARMHook::TRAMPOLINE ARMHook::local_trampoline;
ARMHook::TRAMPOLINE ARMHook::remote_trampoline;

uintptr_t ARMHook::getLibraryAddress(const char* szLibName)
{
	char szPath[0xff] = { 0 };
	char szBuffer[0xfff] = { 0 };
	FILE* fp = nullptr;
	uintptr_t address = 0x00;

	sprintf(szPath, "/proc/%d/maps", getpid());

	fp = fopen(szPath, "rt");
	if (fp == 0) {
		goto done;
	}

	while (fgets(szBuffer, sizeof(szBuffer), fp))
	{
		if (strstr(szBuffer, szLibName)) {
			address = (uintptr_t)strtoul(szBuffer, 0, 16);
			break;
		}
	}

done:
	if (fp) {
		fclose(fp);
	}

	return address;
}

uint8_t ARMHook::getByteSumFromAddress(uintptr_t dest, uint16_t count)
{
	uint8_t sum = 0;
	uint16_t byte = 0;
	while (byte != count)
		sum ^= *(uint8_t*)(dest + byte++) & 0xCC;

	return sum;
}

uintptr_t ARMHook::getSymbolAddress(const char* library, const char* symbol)
{
	void* handle = dlopen(library, RTLD_LAZY);
	if (handle) {
		return (uintptr_t)dlsym(handle, symbol);
	}
	return 0;
}

void ARMHook::initializeTrampolines(uintptr_t _trampoline, size_t size)
{
	remote_trampoline.base_ptr = (char*)_trampoline;
	remote_trampoline.current_ptr = (uintptr_t)remote_trampoline.base_ptr;
	remote_trampoline.size = size;

	local_trampoline.base_ptr = new char[TRAMPOLINE_SIZE];
	local_trampoline.current_ptr = (uintptr_t)local_trampoline.base_ptr;
	local_trampoline.size = TRAMPOLINE_SIZE;
}

void ARMHook::uninitializeTrampolines()
{
	if (local_trampoline.base_ptr) {
		delete local_trampoline.base_ptr;
	}
	local_trampoline.base_ptr = 0x00;
	local_trampoline.current_ptr = 0x00;
	local_trampoline.size = 0;

	remote_trampoline.base_ptr = 0x00;
	remote_trampoline.current_ptr = 0x00;
	remote_trampoline.size = 0;
}

void ARMHook::unprotect(uintptr_t addr)
{
	mprotect((void*)(addr & 0xFFFFF000), PAGE_SIZE, PROT_READ | PROT_WRITE | PROT_EXEC);
}

void ARMHook::makeNOP(uintptr_t addr, unsigned int word_count)
{
	unprotect(addr);

	for (uintptr_t ptr = addr; ptr != (addr + (word_count * 2)); ptr += 2)
	{
		*(uint8_t*)ptr = 0x00;
		*(uint8_t*)(ptr + 1) = 0xBF;
	}
}

void ARMHook::makeRET(uintptr_t func)
{
	writeMemory(func, (uintptr_t)"\x00\x20\xF7\x46", 4);
}

void ARMHook::writeMemory(uintptr_t dest, uintptr_t src, size_t size)
{
	unprotect(dest);
	unprotect(dest + size);
	memcpy((void*)dest, (void*)src, size);
	cacheflush(dest, dest + size, 0);
}

void ARMHook::readMemory(uintptr_t dest, uintptr_t src, size_t size)
{
	unprotect(dest);
	unprotect(dest + size);
	memcpy((void*)dest, (void*)src, size);
}

void ARMHook::installMethodHook(uintptr_t addr, uintptr_t hook_func, uintptr_t* orig_func)
{
	unprotect(addr);
	if (orig_func) *orig_func = *(uintptr_t*)addr;
	*(uintptr_t*)addr = hook_func;
}

void ARMHook::installPLTHook(uintptr_t addr, uintptr_t hook_func, uintptr_t* orig_func)
{
	unprotect(addr);
	if (orig_func) {
		*orig_func = *(uintptr_t*)addr;
	}
	*(uintptr_t*)addr = hook_func;
}

bool ARMHook::installHook(uintptr_t func, uintptr_t hook_func, uintptr_t* orig_func, size_t tramp_size)
{
	if (tramp_size < 4) return false;
	if ((local_trampoline.current_ptr - (uintptr_t)local_trampoline.base_ptr)
		>= (local_trampoline.size - (JUMP_CODE_SIZE + tramp_size))) return false;
	if ((remote_trampoline.current_ptr - (uintptr_t)remote_trampoline.base_ptr)
		>= (remote_trampoline.size - JUMP_CODE_SIZE)) return false;

	readMemory(local_trampoline.current_ptr, func, tramp_size);
	makeJump(local_trampoline.current_ptr + tramp_size, func + tramp_size);
	if(orig_func) *orig_func = local_trampoline.current_ptr + 1;
	local_trampoline.current_ptr += tramp_size + JUMP_CODE_SIZE;

	makeBranch(func, remote_trampoline.current_ptr);
	makeJump(remote_trampoline.current_ptr, hook_func);
	remote_trampoline.current_ptr += JUMP_CODE_SIZE;

	return true;
}

void ARMHook::codeInject(uintptr_t addr, uintptr_t func, int reg)
{
	char instructions[12];

	// adr register, #4
	instructions[0] = 0x01;
	instructions[1] = 0xA0 + reg;
	// ldr register, [register]
	instructions[2] = (0x08 * reg) + reg;
	instructions[3] = 0x68;
	// mov pc, register
	instructions[4] = 0x87 + (0x08 * reg);
	instructions[5] = 0x46;
	// padding[2]
	instructions[6] = instructions[4];
	instructions[7] = instructions[5];
	// function address
	*(uintptr_t*)&instructions[8] = func;

	writeMemory(addr, (uintptr_t)instructions, 12);
}

void ARMHook::codeInject2(uintptr_t addr, uintptr_t func, int reg)
{
	char instructions[2];

	MOV(func, reg, 0);
	MOV(func >> 16, reg, 0);

	instructions[0] = 0x47;
	instructions[1] = 0x80 + (0x08 * reg);

	writeMemory(addr, (uintptr_t)instructions, 10);
}

void ARMHook::makeBranch(uintptr_t func, uintptr_t addr)
{
	uint32_t instruction = ((addr - func - 4) >> 12) & 0x7FF | 0xF000 |
		((((addr - func - 4) >> 1) & 0x7FF | 0xB800) << 16);

	writeMemory(func, (uintptr_t)&instruction, 4);
}

void ARMHook::makeJump(uintptr_t addr, uintptr_t func)
{
	char instructions[JUMP_CODE_SIZE];
	memcpy(instructions, JUMP_CODE, JUMP_CODE_SIZE);
	*(uintptr_t*)&instructions[12] = (func | 0x1);
	writeMemory(addr, (uintptr_t)instructions, JUMP_CODE_SIZE);
}

void ARMHook::MOV(uintptr_t addr, int word, int reg)
{
	unprotect(addr);
	unprotect(addr + 4);

	*(uint8_t*)(addr + 2) = ((uint8_t*)&word)[0]; // lobyte
	auto hibyte = ((uint8_t*)&word)[1];
	*(uint8_t*)(addr) = 0x40 + (hibyte / 0x10);

	if (hibyte - ((hibyte / 0x10) * 0x10) < 0x8)
	{
		*(uint8_t*)(addr + 1) = 0xF2;
		*(uint8_t*)(addr + 3) = (hibyte - ((hibyte / 0x10) * 0x10)) * 0x10 + reg;
	}
	else
	{
		*(uint8_t*)(addr + 1) = 0xF6;
		*(uint8_t*)(addr + 3) = ((hibyte - ((hibyte / 0x10) * 0x10)) - 0x8) * 0x10 + reg;
	}

	cacheflush(addr, addr + 4, 0);
}

void ARMHook::redirectCode(uintptr_t address, uintptr_t newAddress, bool isThumb)
{
	if (isThumb)
	{
		char code[12];
		size_t size = 0;

		if (address % 4 == 0)
		{
			*(uint32_t*)(code + 0) = 0xF000F8DF;
			*(const void**)(code + 4) = (const void*)newAddress;
			ARMHook::writeMemory(address, (uintptr_t)code, 8);
		}
		else
		{
			*(uint32_t*)(code + 0) = 0xBF00;
			*(uint32_t*)(code + 2) = 0xF000F8DF;
			*(const void**)(code + 6) = (const void*)newAddress;
			ARMHook::writeMemory(address, (uintptr_t)code, 10);
		}
		return;
	}

	char code[8];
	*(uint32_t*)(code + 0) = 0xE51FF004;
	*(const void**)(code + 4) = (const void*)newAddress;
	ARMHook::writeMemory(address, (uintptr_t)code, sizeof(code));
}