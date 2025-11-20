#!/usr/bin/env python3
import binascii
import secret


def _step(x, y, z):
    return (x * z + y) & 0xFF


def _mask_bytes(payload: bytes, x: int, y: int, seed: int) -> bytes:
    s = seed & 0xFF
    out = bytearray()
    for b in payload:
        s = _step(x, y, s)
        out.append(b ^ s)
    return bytes(out)


def main():
    msg1, msg2, flag, A, C, SEED = secret.get_secret_material()

    ct1 = _mask_bytes(msg1, A, C, SEED)
    ct2 = _mask_bytes(msg2, A, C, SEED)
    ct3 = _mask_bytes(flag, A, C, SEED)

    print("PLAIN1_HEX =", msg1.hex())
    print("CIPH1_HEX  =", ct1.hex())
    print("CIPH2_HEX  =", ct2.hex())
    print("CIPH3_HEX  =", ct3.hex())


if __name__ == "__main__":
    main()

