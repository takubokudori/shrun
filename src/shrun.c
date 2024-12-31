#include "shrun.h"

uint8_t *AllocateMap(const size_t size) {
    uint8_t *buf;
#ifdef _WINDOWS
    buf = VirtualAlloc(NULL, size, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    if (!buf) {
        printf("VirtualAlloc failed: %lu\n", GetLastError());
        return NULL;
    }
#else
    buf = mmap(NULL, size, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_SHARED | MAP_ANON, -1, 0);
    if (buf == MAP_FAILED) {
        printf("mmap failed: %s\n", strerror(errno));
        return NULL;
    }
#endif
    return buf;
}

/* Free `buf`. Returns 0 on success, 1 on failure. */
uint32_t FreeMap(const uint8_t *buf, const size_t n) {
#ifdef _WINDOWS
    if (!VirtualFree((LPVOID) buf, 0, MEM_RELEASE)) {
        printf("VirtualFree failed: %lu\n", GetLastError());
        return 1;
    }
#else
    if (munmap((void *) buf, n) == -1) {
        printf("munmap failed: %d(%s)\n", errno, strerror(errno));
        return 1;
    }
#endif
    return 0;
}

/* Run the shellcode in `code` and returns the return value of the shellcode.
 * If the shellcode does not set a return value, this value can be a random value.
 */
size_t RunShCode(const uint8_t *code) {
    size_t rax = (*(size_t (*)(void)) code)();

    return rax;
}

// Thread-unsafe
uint8_t *shcode = NULL;

/* Set shellcode. This function must be called before RunShCodeArgs. */
void SetShCodeArgs(uint8_t *code) {
    shcode = code;
}

/* Run the shellcode with args. */
size_t RunShCodeArgs(size_t arg1, ...) {
    if (!shcode) {
        printf("Please set shcode with SetShCodeArgs!\n");
        return 0;
    }
    size_t rax = (*(size_t (*)(void)) shcode)();

    return rax;
}

/* Returns the executable area mapped with shellcode.
 * Returns NULL on failure.
 * The returned area must be freed with `FreeCode`.
 */
uint8_t *MapCode(const uint8_t *code, const size_t n, uint8_t isSetBreakpoint) {
    // 0x20 is an extra size used for things like inserting an int 3 instruction.
    uint8_t *m = AllocateMap(n + 0x20);

    if (!m) return NULL;

    uint8_t *it = m;

    if (isSetBreakpoint) {
        *(it++) = 0xcc; // int 3
    }

    memcpy(it, code, n);
    return m;
}

/* Free the area reserved by `MapCode`.
 * Returns 0 on success, 1 on failure.
 */
uint32_t FreeCode(uint8_t *code, const size_t n) {
    return FreeMap(code, n + 0x20);
}
