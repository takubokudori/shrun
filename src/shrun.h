#include <stdio.h>
#include <stdint.h>

#ifdef _WINDOWS

#include <Windows.h>

#else

#include <string.h>
#include <errno.h>
#include <malloc.h>
#include <sys/mman.h>

#endif

#define RUN_SH_CODE() (RunShCode())
#define RUN_SH_CODE_ARGS(arg1, ...) (RunShCodeArgs((size_t)arg1, __VA_ARGS__))

extern uint8_t *MapCode(const uint8_t *code, size_t n, uint8_t isSetBreakpoint);

extern uint32_t FreeCode(uint8_t *code, size_t n);

extern size_t RunShCode(const uint8_t *code);

extern void SetShCodeArgs(uint8_t *code);

extern size_t RunShCodeArgs(size_t arg1, ...);
