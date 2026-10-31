# -*- coding: utf-8 -*-
"""纯 Python AES-256-GCM（解密方向），零第三方依赖。
仅用于解密 ZCode 凭据这类短文本；GCM tag 校验保证正确性。
"""
SBOX = bytes.fromhex(
    "637c777bf26b6fc53001672bfed7ab76ca82c97dfa5947f0add4a2af9ca472c0"
    "b7fd9326363ff7cc34a5e5f171d8311504c723c31896059a071280e2eb27b275"
    "09832c1a1b6e5aa0523bd6b329e32f8453d100ed20fcb15b6acbbe394a4c58cf"
    "d0efaafb434d338545f9027f503c9fa851a3408f929d38f5bcb6da2110fff3d2"
    "cd0c13ec5f974417c4a77e3d645d197360814fdc222a908846eeb814de5e0bdb"
    "e0323a0a4906245cc2d3ac629195e479e7c8376d8dd54ea96c56f4ea657aae08"
    "ba78252e1ca6b4c6e8dd741f4bbd8b8a703eb5664803f60e613557b986c11d9e"
    "e1f8981169d98e949b1e87e9ce5528df8ca1890dbfe6426841992d0fb054bb16")
RCON = (0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36, 0x6C, 0xD8)


def _xt(a):
    a <<= 1
    return (a ^ 0x1B) & 0xFF if a & 0x100 else a


def expand_key_256(key):
    """AES-256 密钥扩展，返回 15 个轮密钥，每个是 16 字节 list（列主序 state 布局）。"""
    assert len(key) == 32
    w = [list(key[i * 4:i * 4 + 4]) for i in range(8)]
    for i in range(8, 60):
        t = list(w[i - 1])
        if i % 8 == 0:
            t = [SBOX[b] for b in t[1:] + t[:1]]
            t[0] ^= RCON[i // 8 - 1]
        elif i % 8 == 4:
            t = [SBOX[b] for b in t]
        w.append([w[i - 8][j] ^ t[j] for j in range(4)])
    rks = []
    for r in range(15):
        rk = [0] * 16
        for c in range(4):          # state 列 c 与字 w[4r+c] 相加
            for row in range(4):
                rk[row + 4 * c] = w[4 * r + c][row]
        rks.append(rk)
    return rks


def _encrypt_block(rk, block):
    """AES-256 单块加密。rk 为 expand_key_256 输出；block 为 16 字节。"""
    s = [block[i] ^ rk[0][i] for i in range(16)]
    for rnd in range(1, 15):
        s = [SBOX[b] for b in s]
        if rnd < 14:
            # 最后一轮只省略 MixColumns；ShiftRows 每轮都要做
            # ShiftRows: s'[r + 4c] = s[r + 4*((c + r) % 4)]（列主序布局）
            shifted = [0] * 16
            for r in range(4):
                for c in range(4):
                    shifted[r + 4 * c] = s[r + 4 * ((c + r) % 4)]
            s = shifted
            # MixColumns（逐列）
            for c in range(4):
                a = s[4 * c:4 * c + 4]
                t = a[0] ^ a[1] ^ a[2] ^ a[3]
                s[4 * c + 0] = a[0] ^ t ^ _xt(a[0] ^ a[1])
                s[4 * c + 1] = a[1] ^ t ^ _xt(a[1] ^ a[2])
                s[4 * c + 2] = a[2] ^ t ^ _xt(a[2] ^ a[3])
                s[4 * c + 3] = a[3] ^ t ^ _xt(a[3] ^ a[0])
        elif rnd == 14:
            shifted = [0] * 16
            for r in range(4):
                for c in range(4):
                    shifted[r + 4 * c] = s[r + 4 * ((c + r) % 4)]
            s = shifted
        s = [s[i] ^ rk[rnd][i] for i in range(16)]
    return bytes(s)


def _inc32(b):
    ctr = (int.from_bytes(b[12:], "big") + 1) & 0xFFFFFFFF
    return b[:12] + ctr.to_bytes(4, "big")


def _gmul(x, y):
    """GF(2^128) 乘法，用于 GHASH。x、y 为 16 字节。"""
    z = 0
    v = int.from_bytes(x, "big")
    y = int.from_bytes(y, "big")
    for i in range(127, -1, -1):
        bit = (y >> i) & 1
        if bit:
            z ^= v
        if v & 1:
            v = (v >> 1) ^ (0xE1 << 120)
        else:
            v >>= 1
    return z.to_bytes(16, "big")


def gcm_decrypt(key, nonce, ct, tag, aad=b""):
    """AES-256-GCM 解密 + tag 校验。失败抛 ValueError。"""
    rk = expand_key_256(key)
    h = _encrypt_block(rk, b"\x00" * 16)

    j0 = nonce + b"\x00\x00\x00\x01"                      # 96-bit nonce 的 J0
    enc_j0 = _encrypt_block(rk, j0)

    # CTR 从 inc32(J0) 开始
    plaintext = bytearray()
    ctr = _inc32(j0)
    for off in range(0, len(ct), 16):
        ks = _encrypt_block(rk, ctr)
        chunk = ct[off:off + 16]
        plaintext += bytes(a ^ b for a, b in zip(chunk, ks))
        ctr = _inc32(ctr)

    # GHASH(AAD || CT || len)
    def pad16(b):
        return b + b"\x00" * ((16 - len(b) % 16) % 16)

    ghash = b"\x00" * 16
    for chunk in (pad16(aad), pad16(bytes(ct))):
        for off in range(0, len(chunk), 16):
            blk = chunk[off:off + 16]
            ghash = _gmul(bytes(a ^ b for a, b in zip(ghash, blk)), h)
    lens = (len(aad) * 8).to_bytes(8, "big") + (len(ct) * 8).to_bytes(8, "big")
    ghash = _gmul(bytes(a ^ b for a, b in zip(ghash, lens)), h)
    computed = bytes(a ^ b for a, b in zip(ghash, enc_j0))

    if computed != tag:
        raise ValueError("GCM tag 校验失败")
    return bytes(plaintext)


if __name__ == "__main__":
    # FIPS-197 AES-256 单块向量
    rk = expand_key_256(bytes.fromhex(
        "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4"))
    got = _encrypt_block(rk, bytes.fromhex("6bc1bee22e409f96e93d7e117393172a"))
    assert got == bytes.fromhex("f3eed1bdb5d2a03c064b5a7e3db181f8"), got.hex()
    print("FIPS-197 单块向量: 通过")
