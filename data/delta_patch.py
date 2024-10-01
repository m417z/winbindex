# Code from:
# https://gist.github.com/wumb0/9542469e3915953f7ae02d63998d2553
# https://wumb0.in/extracting-and-diffing-ms-patches-in-2020.html

from ctypes import (windll, wintypes, c_uint64, cast, POINTER, Union, c_ubyte,
                    LittleEndianStructure, byref, c_size_t, CDLL)
import zlib


# types and flags
DELTA_FLAG_TYPE             = c_uint64
DELTA_FLAG_NONE             = 0x00000000
DELTA_APPLY_FLAG_ALLOW_PA19 = 0x00000001


# structures
class DELTA_INPUT(LittleEndianStructure):
    class U1(Union):
        _fields_ = [('lpcStart', wintypes.LPVOID),
                    ('lpStart', wintypes.LPVOID)]
    _anonymous_ = ('u1',)
    _fields_ = [('u1', U1),
                ('uSize', c_size_t),
                ('Editable', wintypes.BOOL)]


class DELTA_OUTPUT(LittleEndianStructure):
    _fields_ = [('lpStart', wintypes.LPVOID),
                ('uSize', c_size_t)]


# functions
# Use custom msdelta.dll. Refer to msdelta.dll.txt for details.
# msdelta = windll.msdelta
msdelta = CDLL('tools/msdelta.dll')
ApplyDeltaB = msdelta.ApplyDeltaB
ApplyDeltaB.argtypes = [DELTA_FLAG_TYPE, DELTA_INPUT, DELTA_INPUT,
                        POINTER(DELTA_OUTPUT)]
ApplyDeltaB.rettype = wintypes.BOOL
DeltaFree = msdelta.DeltaFree
DeltaFree.argtypes = [wintypes.LPVOID]
DeltaFree.rettype = wintypes.BOOL
gle = windll.kernel32.GetLastError


def apply_patchfile_to_buffer(buf, buflen, patchpath, legacy):
    with open(patchpath, 'rb') as patch:
        patch_contents = patch.read()

    # some patches (Windows Update MSU) come with a CRC32 prepended to the file
    # if the file doesn't start with the signature (PA) then check it
    # if patch_contents[:2] != b"PA":
    #     paoff = patch_contents.find(b"PA")
    #     if paoff != 4:

    # Above is the original code, which breaks if the CRC32 happens to contain
    # "PA". Just assume that the first 4 bytes are the CRC32.
    if True:
        if patch_contents[4:6] != b"PA":
            raise Exception("Patch is invalid")
        crc = int.from_bytes(patch_contents[:4], 'little')
        patch_contents = patch_contents[4:]
        if zlib.crc32(patch_contents) != crc:
            raise Exception("CRC32 check failed. Patch corrupted or invalid")

    applyflags = DELTA_APPLY_FLAG_ALLOW_PA19 if legacy else DELTA_FLAG_NONE

    dd = DELTA_INPUT()
    ds = DELTA_INPUT()
    dout = DELTA_OUTPUT()

    ds.lpcStart = buf
    ds.uSize = buflen
    ds.Editable = False

    dd.lpcStart = cast(patch_contents, wintypes.LPVOID)
    dd.uSize = len(patch_contents)
    dd.Editable = False

    status = ApplyDeltaB(applyflags, ds, dd, byref(dout))
    if status == 0:
        raise Exception("Patch {} failed with error {}".format(patchpath, gle()))

    return (dout.lpStart, dout.uSize)


if __name__ == '__main__':
    import sys
    import base64
    import hashlib
    import argparse

    ap = argparse.ArgumentParser()
    mode = ap.add_mutually_exclusive_group(required=True)
    output = ap.add_mutually_exclusive_group(required=True)
    mode.add_argument("-i", "--input-file",
                      help="File to patch (forward or reverse)")
    mode.add_argument("-n", "--null", action="store_true", default=False,
                      help="Create the output file from a null diff "
                           "(null diff must be the first one specified)")
    output.add_argument("-o", "--output-file",
                        help="Destination to write patched file to")
    output.add_argument("-d", "--dry-run", action="store_true",
                        help="Don't write patch, just see if it would patch"
                             "correctly and get the resulting hash")
    ap.add_argument("-l", "--legacy", action='store_true', default=False,
                    help="Let the API use the PA19 legacy API (if required)")
    ap.add_argument("patches", nargs='+', help="Patches to apply")
    args = ap.parse_args()

    if not args.dry_run and not args.output_file:
        print("Either specify -d or -o", file=sys.stderr)
        ap.print_help()
        sys.exit(1)

    if args.null:
        inbuf = b""
    else:
        with open(args.input_file, 'rb') as r:
            inbuf = r.read()

    buf = cast(inbuf, wintypes.LPVOID)
    n = len(inbuf)
    to_free = []
    try:
        for patch in args.patches:
            buf, n = apply_patchfile_to_buffer(buf, n, patch, args.legacy)
            to_free.append(buf)

        outbuf = bytes((c_ubyte*n).from_address(buf))
        if not args.dry_run:
            with open(args.output_file, 'wb') as w:
                w.write(outbuf)
    finally:
        for buf in to_free:
            DeltaFree(buf)

    finalhash = hashlib.sha256(outbuf)
    print("Applied {} patch{} successfully"
          .format(len(args.patches), "es" if len(args.patches) > 1 else ""))
    print("Final hash: {}"
          .format(base64.b64encode(finalhash.digest()).decode()))


############################################################


from pathlib import Path


def unpack_null_differential_file(input_file: Path, output_file: Path, legacy=False):
    inbuf = b""

    buf = cast(inbuf, wintypes.LPVOID)
    n = len(inbuf)
    to_free = []
    try:
        for patch in [input_file]:
            buf, n = apply_patchfile_to_buffer(buf, n, patch, legacy)
            to_free.append(buf)

        outbuf = bytes((c_ubyte*n).from_address(buf))
        with open(output_file, 'wb') as w:
            w.write(outbuf)
    finally:
        for buf in to_free:
            DeltaFree(buf)
