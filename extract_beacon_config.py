"""Static Beacon config extraction for the goopdate.dll loader in this campaign.

Usage: python -I extract_beacon_config.py goopdate.dll

Nothing is executed. Steps:
1. take the longest base64 string in the loader (.rdata) and decode it
2. layout: u32 version, u32 key_len (192), u32 size, u32 size, key[key_len], body[size]
3. body XOR key (repeating) -> Beacon PE (MZ patched to 'AIBJ', PE sig to 'CS', sections obfuscated)
4. Beacon config is XOR 0x2e; entries are TLV (u16 id, u16 type, u16 len) in shuffled order,
   so find the chain by walking rather than by the first entry
"""

import base64
import hashlib
import json
import re
import struct
import sys

NAMES = {
    1: "BeaconType",
    2: "Port",
    3: "SleepTime_ms",
    4: "MaxGetSize",
    5: "Jitter_pct",
    7: "PublicKey",
    8: "C2Server",
    9: "UserAgent",
    10: "PostURI",
    12: "HttpGet_Metadata",
    13: "HttpPost_Metadata",
    26: "HttpGet_Verb",
    27: "HttpPost_Verb",
    29: "Spawnto_x86",
    30: "Spawnto_x64",
    37: "Watermark",
    38: "bStageCleanup",
    50: "bUsesCookies",
}


def decrypt(loader: bytes) -> bytes:
    blob = max(
        re.finditer(rb"[A-Za-z0-9+/=]{1000,}", loader), key=lambda m: len(m.group())
    ).group()
    raw = base64.b64decode(blob)
    _ver, klen, size, _ = struct.unpack("<4I", raw[:16])
    key, body = raw[16 : 16 + klen], raw[16 + klen : 16 + klen + size]
    return bytes(c ^ key[i % klen] for i, c in enumerate(body))


def walk(x: bytes, o: int):
    out, i = [], o
    while True:
        idx, typ, ln = struct.unpack(">HHH", x[i : i + 6])
        if idx == 0:
            return out
        if typ not in (1, 2, 3) or ln > 4096 or idx > 0x100:
            return None
        out.append((idx, typ, x[i + 6 : i + 6 + ln]))
        i += 6 + ln


def config(beacon: bytes) -> dict:
    x = bytes(b ^ 0x2E for b in beacon)
    best = []
    for o in range(0, len(x) - 6, 2):
        if x[o] != 0 or x[o + 2] != 0 or x[o + 3] not in (1, 2, 3):
            continue
        r = walk(x, o)
        if r and len(r) > len(best):
            best = r
    cfg = {}
    for idx, typ, v in best:
        if idx not in NAMES:
            continue
        if typ == 1:
            val = struct.unpack(">H", v)[0]
        elif typ == 2:
            val = struct.unpack(">I", v)[0]
        elif idx == 7:
            der = v[: 3 + v[2]]
            val = {"der_sha256": hashlib.sha256(der).hexdigest()}
        elif idx in (12, 13):
            val = [s.decode() for s in re.findall(rb"[\x20-\x7e]{4,}", v)]
        else:
            val = v.rstrip(b"\0").decode("latin-1")
        cfg[NAMES[idx]] = val
    return cfg


if __name__ == "__main__":
    print(json.dumps(config(decrypt(open(sys.argv[1], "rb").read())), indent=2))
