#!/usr/bin/python3
from ctypes import *
import os

if os.name == 'nt':
    DEFAULT_PATH_TO_SHRUN = "shrun.dll"
else:
    DEFAULT_PATH_TO_SHRUN = "shrun.so"

lib_shrun: CDLL = None


def load_lib_shrun(path_to_lib: str):
    global lib_shrun
    lib_shrun = CDLL(path_to_lib)
    lib_shrun.MapCode.argtypes = (POINTER(c_ubyte), c_size_t, c_int)
    lib_shrun.MapCode.restype = c_void_p
    lib_shrun.FreeCode.argtypes = (POINTER(c_ubyte), c_size_t)
    lib_shrun.FreeCode.restype = c_int
    lib_shrun.RunShCode.argtypes = (c_void_p,)
    lib_shrun.RunShCode.restype = c_size_t
    lib_shrun.SetShCodeArgs.argtypes = (c_void_p,)
    lib_shrun.SetShCodeArgs.restype = None
    lib_shrun.RunShCodeArgs.argtypes = None
    lib_shrun.RunShCodeArgs.restype = c_size_t


class Shrun:
    m: c_void_p
    code_len: int

    def __init__(self, code: bytes, path_to_lib: str = None, is_set_breakpoint: bool = False):
        global lib_shrun
        self.m = 0
        if lib_shrun is None:
            if path_to_lib is not None:
                load_lib_shrun(path_to_lib)
            else:
                load_lib_shrun(DEFAULT_PATH_TO_SHRUN)
        self.code_len = len(code)
        self.m = lib_shrun.MapCode(cast(c_char_p(code), POINTER(c_ubyte)), len(code),
                                   is_set_breakpoint)
        if self.m == 0:
            raise RuntimeError("Shrun MapCode failed")

    def run(self) -> c_size_t:
        global lib_shrun
        return lib_shrun.RunShCode(self.m)

    def run_with_args(self, *args) -> c_size_t:
        global lib_shrun
        lib_shrun.SetShCodeArgs(self.m)
        return lib_shrun.RunShCodeArgs(*args)

    def __del__(self):
        global lib_shrun
        if self.m == 0:
            return
        ret = lib_shrun.FreeCode(cast(self.m, POINTER(c_ubyte)), self.code_len)
        if ret != 0:
            raise RuntimeError("Shrun FreeCode failed")


# Example
def main():
    import sys
    is_set_breakpoint = False
    if len(sys.argv) >= 2 and sys.argv[1] == '-b':
        is_set_breakpoint = True

    # Run shellcode without args
    with open('./examples/ret0x12345678-x64.bin', 'rb') as f:
        shcode = f.read()
    code = Shrun(shcode, is_set_breakpoint=is_set_breakpoint)
    ret = code.run()
    print(f'ret = 0x{ret:016x}')

    # Run shellcode with args
    if os.name == 'nt':
        with open('./examples/memcpy-x64-windows.bin', 'rb') as f:
            shcode = f.read()
    else:
        with open('./examples/memcpy-x64-linux.bin', 'rb') as f:
            shcode = f.read()
    code = Shrun(shcode, is_set_breakpoint=is_set_breakpoint)
    a1 = b"abcde"
    a2 = b"xyz"
    print(f'{a1=}')  # b'abcde'
    ret = code.run_with_args(a1, a2, 3)
    print(f'ret = 0x{ret:016x}')
    print(f'{a1=}')  # b'xyzde'


if __name__ == '__main__':
    main()
