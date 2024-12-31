#include "shrun.h"

uint8_t setBreakpoint = 0;
uint8_t printVerbose = 0;

void DumpHex(const uint8_t *code, const size_t n) {
    for (size_t i = 0; i < n; i++) {
        printf("%02x ", code[i]);
    }
    printf("\n");
}

void Usage(char **argv) {
    printf("Usage: %s <shellcode file>\n"
           "\n"
           "Options:\n"
           "    -b: Set a breakpoint before the shellcode entrypoint (x86/x64 only)\n"
           "    -v: Verbose\n"
           "    -h: Show help\n"
           "", argv[0]);
}

uint8_t *ReadFromFile(char *fname, uint32_t *size) {
    FILE *fp = fopen(fname, "rb");
    if (!fp) {
        printf("Failed to open %s: %s\n", fname, strerror(errno));
        return NULL;
    }

    fseek(fp, 0, SEEK_END);
    long sz = ftell(fp);
    fseek(fp, 0, SEEK_SET);

    uint8_t *buf = malloc(sz);
    if (!buf) {
        printf("Allocate failed\n");
        fclose(fp);
        return NULL;
    }

    memset(buf, 0, sz);
    if (fread(buf, sizeof(uint8_t), sz, fp) != sz) {
        free(buf);
        fclose(fp);
        return NULL;
    }

    fclose(fp);
    *size = sz;
    uint8_t *code = MapCode(buf, sz, setBreakpoint);

    if (!code) {
        printf("MapCode failed\n");
        free(buf);
        return NULL;
    }
    free(buf);
    return code;
}

int main(int argc, char **argv) {
    uint8_t *code = NULL;
    char *fname = NULL;
    uint32_t sz = 0;

    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "-b")) setBreakpoint = 1;
        else if (!strcmp(argv[i], "-v")) printVerbose = 1;
        else if (!strcmp(argv[i], "-h") || !strcmp(argv[i], "--help")) {
            Usage(argv);
            return 0;
        } else {
            fname = argv[i];
        }
    }

    if (!fname) {
        Usage(argv);
        return 0;
    }

    if (code = ReadFromFile(fname, &sz), !code) {
        printf("ReadFromFile failed\n");
        return 1;
    }

    if (printVerbose) {
        printf("size=%u\n", sz);
        DumpHex(code, sz);
    }

    printf("shell code address=%p\n", code);
    size_t ret;
    ret = RunShCode(code);
    printf("ret=0x%zx\n", ret);

    /*
    // Pass the arguments
    char a1[] = "abcde";
    char a2[] = "xyz";
    SetShCodeArgs(code);
    printf("a1 =0x%p, [a1]=%s\n", a1, a1);
    ret = RUN_SH_CODE_ARGS(a1, a2, 3);
    printf("ret=0x%p, [a1]=%s\n", (void *) ret, a1);
    */
    FreeCode(code, sz);
    return 0;
}
