#pragma once

#include <jni.h>
#include <pthread.h>
#include <syscall.h>
#include <algorithm>
#include <dlfcn.h>
#include <cstdlib>
#include <cstdio>
#include <vector>
#include <list>
#include <string>
#include <sstream>
#include <unistd.h>
#include <android/log.h>

#include "vendor/armhook/armhook.h"

#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, "reSA", __VA_ARGS__)
#define LOGW(...) __android_log_print(ANDROID_LOG_WARN, "reSA", __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, "reSA", __VA_ARGS__)

extern uintptr_t g_libGTASA;