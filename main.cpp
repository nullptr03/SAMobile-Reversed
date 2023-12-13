#include "main.h"

uintptr_t g_libGTASA = 0x00;

void* Init(void*)
{
	pthread_exit(0);
}

jint JNI_OnLoad(JavaVM* vm, void* reserved)
{
	LOGI("Reversed library loaded! Build time: " __DATE__ " " __TIME__);

	g_libGTASA = ARMHook::getLibraryAddress("libGTASA.so");
	if (g_libGTASA == 0x00) return JNI_VERSION_1_4;

	ARMHook::makeRET(g_libGTASA + 0x3F6580);
	ARMHook::initializeTrampolines(g_libGTASA + 0x3F6584, 0x2D2);

	pthread_t thread;
	pthread_create(&thread, 0, Init, 0);
	return JNI_VERSION_1_4;
}

// never called on Android :(
void JNI_OnUnload(JavaVM *vm, void *reserved)
{
	ARMHook::uninitializeTrampolines();
}
