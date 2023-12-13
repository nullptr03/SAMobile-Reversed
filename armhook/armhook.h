#pragma once

class ARMHook
{
public:
	static void unprotect(uintptr_t addr);
	/* 1 nop = 2 bytes */
	static void makeNOP(uintptr_t addr, unsigned int word_count);
	/* 2 bytes */
	static void makeRET(uintptr_t addr);

	static void writeMemory(uintptr_t dest, uintptr_t src, size_t size);
	static void readMemory(uintptr_t dest, uintptr_t src, size_t size);

	static void installMethodHook(
		uintptr_t addr,
		uintptr_t hook_func,
		uintptr_t* orig_func = nullptr
	);

	static void installPLTHook(
		uintptr_t addr,
		uintptr_t hook_func,
		uintptr_t* orig_func = nullptr
	);

	static bool installHook(
		uintptr_t func,
		uintptr_t hook_func,
		uintptr_t* orig_func = nullptr,
		size_t tramp_size = 4
	);
	
	static void codeInject(
		uintptr_t addr,
		uintptr_t func,
		int reg
	);
	static void codeInject2(
		uintptr_t addr,
		uintptr_t func,
		int reg
	);

	static void redirectCode(uintptr_t address, uintptr_t newAddress, bool isThumb);

	static uintptr_t getLibraryAddress(const char* szLibName);

	static uint8_t getByteSumFromAddress(uintptr_t dest, uint16_t count);
	static uintptr_t getSymbolAddress(const char* library, const char* symbol);

	static void initializeTrampolines(uintptr_t _trampoline, size_t size);
	static void uninitializeTrampolines();

private:
	struct TRAMPOLINE
	{
		char* base_ptr;
		uintptr_t	current_ptr;
		size_t		size;
	};

	static struct TRAMPOLINE local_trampoline;
	static struct TRAMPOLINE remote_trampoline;

	static void makeBranch(uintptr_t func, uintptr_t addr);
	static void makeJump(uintptr_t addr, uintptr_t func);
	static void MOV(uintptr_t addr, int word, int reg);
};