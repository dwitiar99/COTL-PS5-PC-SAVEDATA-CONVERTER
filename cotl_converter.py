#!/usr/bin/env python3
"""
CotL Save Converter - Cult of the Lamb save converter (PC <-> PS5)

Single file, standard library only (AES-128-CBC is implemented in pure Python).

  PC -> PS5 : decrypts the PC save files and wraps them in the PS5 container format.
  PS5 -> PC : unwraps the PS5 data files and encrypts them in the PC format.

Format knowledge: the PC encryption layout is documented by Matteo Fattorini's
cotl-save-editor (MIT) - https://github.com/Matteo-Fattorini/cotl-save-editor
This tool is an independent implementation and is not affiliated with Massive Monster.
"""
import argparse
import gzip
import json
import os
import re
import shutil
import sys
import tempfile
import time
import zipfile

__version__ = "1.0.0"
BOM = b"\xef\xbb\xbf"
LANG = "en"


def t(en, idn):
    return idn if LANG == "id" else en


class ConvError(Exception):
    pass


# ----------------------------------------------------------------------------
# AES-128-CBC (pure Python)
# ----------------------------------------------------------------------------
def _build_sbox():
    sbox = [0] * 256
    p = q = 1
    while True:
        p = (p ^ (p << 1) ^ (0x11B if p & 0x80 else 0)) & 0xFF
        q = (q ^ (q << 1)) & 0xFF
        q = (q ^ (q << 2)) & 0xFF
        q = (q ^ (q << 4)) & 0xFF
        if q & 0x80:
            q ^= 0x09

        def rot(v, n):
            return ((v << n) | (v >> (8 - n))) & 0xFF

        sbox[p] = q ^ rot(q, 1) ^ rot(q, 2) ^ rot(q, 3) ^ rot(q, 4) ^ 0x63
        if p == 1:
            break
    sbox[0] = 0x63
    inv = [0] * 256
    for i, v in enumerate(sbox):
        inv[v] = i
    return sbox, inv


def _gmul(a, b):
    r = 0
    while b:
        if b & 1:
            r ^= a
        a = (((a << 1) ^ 0x11B) & 0xFF) if (a & 0x80) else ((a << 1) & 0xFF)
        b >>= 1
    return r


SBOX, INV_SBOX = _build_sbox()
_M = {k: [_gmul(x, k) for x in range(256)] for k in (2, 3, 9, 11, 13, 14)}
M2, M3, M9, M11, M13, M14 = (_M[k] for k in (2, 3, 9, 11, 13, 14))


def _expand_key(key):
    if len(key) != 16:
        raise ValueError("AES-128 key must be 16 bytes")
    w = [list(key[i:i + 4]) for i in range(0, 16, 4)]
    rcon = 1
    for i in range(4, 44):
        tmp = w[i - 1][:]
        if i % 4 == 0:
            tmp = [SBOX[b] for b in tmp[1:] + tmp[:1]]
            tmp[0] ^= rcon
            rcon = M2[rcon]
        w.append([a ^ b for a, b in zip(w[i - 4], tmp)])
    return [sum(w[4 * r:4 * r + 4], []) for r in range(11)]


def _enc_block(rk, blk):
    s = [b ^ k for b, k in zip(blk, rk[0])]
    for r in range(1, 11):
        s = [SBOX[b] for b in s]
        s = [s[(i + 4 * (i % 4)) % 16] for i in range(16)]
        if r != 10:
            n = []
            for c in range(0, 16, 4):
                a0, a1, a2, a3 = s[c:c + 4]
                n += [M2[a0] ^ M3[a1] ^ a2 ^ a3,
                      a0 ^ M2[a1] ^ M3[a2] ^ a3,
                      a0 ^ a1 ^ M2[a2] ^ M3[a3],
                      M3[a0] ^ a1 ^ a2 ^ M2[a3]]
            s = n
        s = [b ^ k for b, k in zip(s, rk[r])]
    return bytes(s)


def _dec_block(rk, blk):
    s = [b ^ k for b, k in zip(blk, rk[10])]
    for r in range(9, -1, -1):
        n = [0] * 16
        for i in range(16):
            n[(i + 4 * (i % 4)) % 16] = s[i]
        s = [INV_SBOX[b] for b in n]
        s = [b ^ k for b, k in zip(s, rk[r])]
        if r != 0:
            n = []
            for c in range(0, 16, 4):
                a0, a1, a2, a3 = s[c:c + 4]
                n += [M14[a0] ^ M11[a1] ^ M13[a2] ^ M9[a3],
                      M9[a0] ^ M14[a1] ^ M11[a2] ^ M13[a3],
                      M13[a0] ^ M9[a1] ^ M14[a2] ^ M11[a3],
                      M11[a0] ^ M13[a1] ^ M9[a2] ^ M14[a3]]
            s = n
    return bytes(s)


def cbc_encrypt(key, iv, data):
    rk = _expand_key(key)
    padn = 16 - (len(data) % 16)
    data = data + bytes([padn]) * padn
    out, prev = [], iv
    for i in range(0, len(data), 16):
        prev = _enc_block(rk, bytes(a ^ b for a, b in zip(data[i:i + 16], prev)))
        out.append(prev)
    return b"".join(out)


def cbc_decrypt(key, iv, data):
    if len(data) == 0 or len(data) % 16:
        raise ValueError("ciphertext length is not a multiple of 16")
    rk = _expand_key(key)
    out, prev = [], iv
    for i in range(0, len(data), 16):
        c = data[i:i + 16]
        out.append(bytes(a ^ b for a, b in zip(_dec_block(rk, c), prev)))
        prev = c
    pt = b"".join(out)
    padn = pt[-1]
    if not 1 <= padn <= 16 or pt[-padn:] != bytes([padn]) * padn:
        raise ValueError("bad padding (corrupted file?)")
    return pt[:-padn]


# ----------------------------------------------------------------------------
# PC save container:  0x45 | key(16) | iv(16) | AES-128-CBC ciphertext (PKCS7)
# ----------------------------------------------------------------------------
def pc_decrypt(raw):
    if len(raw) < 49 or raw[0] != 0x45:
        raise ValueError("not an encrypted PC save (missing 0x45 marker)")
    if (len(raw) - 33) % 16:
        raise ValueError("unexpected file size")
    return cbc_decrypt(raw[1:17], raw[17:33], raw[33:])


def pc_encrypt(payload, key=None, iv=None):
    key = key or os.urandom(16)
    iv = iv or os.urandom(16)
    return b"\x45" + key + iv + cbc_encrypt(key, iv, payload)


# ----------------------------------------------------------------------------
# Name mapping PC <-> PS5 (the PS5 side is what the save manager dumps)
# ----------------------------------------------------------------------------
PC_FILE_RE = re.compile(r"(?:(slot|meta)_(\d+)\.mp|persistence\.json|settings\.json)")
PS5_DIR_RE = re.compile(r"sdimg_(?:(slot|meta)-(\d+)mp|persistence|settings|prefs)")


def pc_to_ps5_name(name):
    m = re.fullmatch(r"(slot|meta)_(\d+)\.mp", name)
    if m:
        return "sdimg_%s-%smp" % (m.group(1), m.group(2))
    return "sdimg_" + name.replace(".json", "")


def ps5_to_pc_name(dname):
    m = re.fullmatch(r"sdimg_(slot|meta)-(\d+)mp", dname)
    if m:
        return "%s_%s.mp" % (m.group(1), m.group(2))
    if dname in ("sdimg_persistence", "sdimg_settings"):
        return dname[len("sdimg_"):] + ".json"
    return None


def slot_no(name):
    m = re.search(r"(\d+)", name)
    return m.group(1) if m else None


# ----------------------------------------------------------------------------
# Payload helpers
# ----------------------------------------------------------------------------
def strip_bom(b):
    return b[3:] if b.startswith(BOM) else b


def check_json(b):
    try:
        json.loads(strip_bom(b).decode("utf-8"))
    except Exception as e:
        raise ValueError("decrypted data is not valid JSON: %s" % e)


def check_msgpack(b):
    # root objects are arrays: fixarray / array16 / array32
    if not b or not (0x90 <= b[0] <= 0x9F or b[0] in (0xDC, 0xDD)):
        raise ValueError("decrypted data does not look like MessagePack")


def find_version(meta_payload):
    m = re.search(rb"\d+\.\d+\.\d+(?:\.\d+)?", meta_payload)
    return m.group(0).decode() if m else None


def vtuple(v):
    return tuple(int(x) for x in v.split("."))


def wrap_ps5(name, payload):
    if name.endswith(".mp"):
        check_msgpack(payload)
        return b"MP" + payload
    check_json(payload)
    return b"ZB" + gzip.compress(BOM + strip_bom(payload), mtime=0)


def unwrap_ps5(data):
    tag = data[:2]
    if tag == b"MP":
        return data[2:]
    if tag == b"ZB":
        return strip_bom(gzip.decompress(data[2:]))
    raise ValueError("unknown PS5 data header %r" % tag)


# ----------------------------------------------------------------------------
# File system helpers
# ----------------------------------------------------------------------------
def clean_path(p):
    return p.strip().strip('"').strip("'").strip()


def safe_extract(zpath, dest):
    base = os.path.realpath(dest)
    with zipfile.ZipFile(zpath) as z:
        for m in z.infolist():
            tgt = os.path.realpath(os.path.join(dest, m.filename))
            if tgt != base and not tgt.startswith(base + os.sep):
                raise ConvError(t("Unsafe path inside zip: ", "Path tidak aman di dalam zip: ") + m.filename)
        z.extractall(dest)


def prepare_input(path, tmp):
    path = clean_path(path)
    if os.path.isdir(path):
        return path
    if os.path.isfile(path) and path.lower().endswith(".zip"):
        d = tempfile.mkdtemp(dir=tmp)
        safe_extract(path, d)
        return d
    raise ConvError(t("Not a folder or .zip: ", "Bukan folder atau .zip: ") + path)


def locate(base):
    """Find the shallowest folder that holds PC save files or PS5 sdimg_* folders."""
    for root, dirs, files in os.walk(base):
        if any(d.startswith("sdimg_") for d in dirs):
            return "ps5", root
        if any(PC_FILE_RE.fullmatch(f) for f in files):
            return "pc", root
    return None, None


def unique(path):
    if not os.path.exists(path):
        return path
    i = 2
    while os.path.exists("%s_%d" % (path, i)):
        i += 1
    return "%s_%d" % (path, i)


def make_zip(folder, zpath):
    with zipfile.ZipFile(zpath, "w", zipfile.ZIP_DEFLATED) as z:
        for root, dirs, files in os.walk(folder):
            for d in sorted(dirs):
                full = os.path.join(root, d)
                z.write(full, os.path.relpath(full, folder).replace(os.sep, "/") + "/")
            for f in sorted(files):
                full = os.path.join(root, f)
                z.write(full, os.path.relpath(full, folder).replace(os.sep, "/"))


# ----------------------------------------------------------------------------
# Conversions
# ----------------------------------------------------------------------------
def pc_to_ps5(folder, out, template_root, include_settings, log):
    files = sorted(f for f in os.listdir(folder) if PC_FILE_RE.fullmatch(f))
    if not files:
        raise ConvError(t("No PC save files found.", "File save PC tidak ditemukan."))
    tmpl_dirs = set(os.listdir(template_root)) if template_root else set()
    if template_root:
        shutil.copytree(template_root, out)
    else:
        os.makedirs(out)
        log(t("NOTE: no PS5 template given -> output has only the 'data' files (no sce_sys).",
              "CATATAN: tanpa template PS5 -> hasil hanya berisi file 'data' (tanpa sce_sys)."))
    done = failed = 0
    for name in files:
        if name == "settings.json" and not include_settings:
            log("  - %s: %s" % (name, t("skipped (platform-specific settings)", "dilewati (pengaturan khusus platform)")))
            continue
        dname = pc_to_ps5_name(name)
        if template_root and dname not in tmpl_dirs:
            log("  ! %s: %s" % (name, t("no matching folder '%s' in the PS5 template, skipped" % dname,
                                        "folder '%s' tidak ada di template PS5, dilewati" % dname)))
            failed += 1
            continue
        try:
            payload = pc_decrypt(open(os.path.join(folder, name), "rb").read())
            data = wrap_ps5(name, payload)
        except Exception as e:
            log("  ! %s: %s" % (name, e))
            failed += 1
            continue
        os.makedirs(os.path.join(out, dname), exist_ok=True)
        open(os.path.join(out, dname, "data"), "wb").write(data)
        extra = ""
        if name.startswith("meta_"):
            pcv = find_version(payload)
            extra = "  [%s %s]" % (t("game version", "versi game"), pcv)
            tm = os.path.join(template_root or "", dname, "data")
            if pcv and template_root and os.path.isfile(tm):
                try:
                    psv = find_version(unwrap_ps5(open(tm, "rb").read()))
                except Exception:
                    psv = None
                if psv and vtuple(pcv) > vtuple(psv):
                    extra += "\n    ! " + t(
                        "PC save (%s) is newer than the PS5 save (%s). Update the game on PS5 first." % (pcv, psv),
                        "Save PC (%s) lebih baru dari save PS5 (%s). Update game di PS5 dulu." % (pcv, psv))
        log("  + %s -> %s/data%s" % (name, dname, extra))
        done += 1
    if not done:
        raise ConvError(t("Nothing was converted.", "Tidak ada file yang berhasil dikonversi."))
    return done, failed


def ps5_to_pc(folder, out, include_settings, log):
    dirs = sorted(d for d in os.listdir(folder) if d.startswith("sdimg_") and os.path.isdir(os.path.join(folder, d)))
    if not dirs:
        raise ConvError(t("No PS5 sdimg_* folders found.", "Folder sdimg_* PS5 tidak ditemukan."))
    os.makedirs(out)
    done = failed = 0
    for d in dirs:
        name = ps5_to_pc_name(d)
        if name is None:
            log("  - %s: %s" % (d, t("not used on PC, skipped", "tidak dipakai di PC, dilewati")))
            continue
        if name == "settings.json" and not include_settings:
            log("  - %s: %s" % (d, t("skipped (platform-specific settings)", "dilewati (pengaturan khusus platform)")))
            continue
        p = os.path.join(folder, d, "data")
        if not os.path.isfile(p):
            log("  ! %s: %s" % (d, t("no 'data' file", "tidak ada file 'data'")))
            failed += 1
            continue
        try:
            payload = unwrap_ps5(open(p, "rb").read())
            if name.endswith(".mp"):
                check_msgpack(payload)
            else:
                check_json(payload)
            raw = pc_encrypt(payload)
        except Exception as e:
            log("  ! %s: %s" % (d, e))
            failed += 1
            continue
        open(os.path.join(out, name), "wb").write(raw)
        extra = ""
        if name.startswith("meta_"):
            extra = "  [%s %s]" % (t("game version", "versi game"), find_version(payload))
        log("  + %s -> %s%s" % (d, name, extra))
        done += 1
    if not done:
        raise ConvError(t("Nothing was converted.", "Tidak ada file yang berhasil dikonversi."))
    return done, failed


def run(src, to=None, template=None, out=None, include_settings=False, zip_out=True, log=print):
    """Returns (output_folder, output_zip_or_None, direction)."""
    tmp = tempfile.mkdtemp(prefix="cotlconv_")
    try:
        base = prepare_input(src, tmp)
        kind, root = locate(base)
        if kind is None:
            raise ConvError(t("No Cult of the Lamb save files found in that location.",
                              "Tidak ada file save Cult of the Lamb di lokasi itu."))
        if to is None:
            to = "ps5" if kind == "pc" else "pc"
        if (kind, to) not in (("pc", "ps5"), ("ps5", "pc")):
            raise ConvError(t("Input looks like a %s save, so it cannot be converted to %s." % (kind.upper(), to.upper()),
                              "Input terdeteksi save %s, jadi tidak bisa dikonversi ke %s." % (kind.upper(), to.upper())))
        s = clean_path(src)
        if out is None:
            stem = os.path.splitext(s)[0] if s.lower().endswith(".zip") else s.rstrip("\\/")
            out = unique(stem + "_to_" + to)
        else:
            out = clean_path(out)
            if os.path.exists(out):
                raise ConvError(t("Output already exists: ", "Output sudah ada: ") + out)
        log(t("Detected: %s save  ->  converting to %s" % (kind.upper(), to.upper()),
              "Terdeteksi: save %s  ->  dikonversi ke %s" % (kind.upper(), to.upper())))
        if to == "ps5":
            troot = None
            if template:
                tbase = prepare_input(template, tmp)
                tk, troot = locate(tbase)
                if tk != "ps5":
                    raise ConvError(t("The PS5 template does not contain sdimg_* folders.",
                                      "Template PS5 tidak berisi folder sdimg_*."))
            n, bad = pc_to_ps5(root, out, troot, include_settings, log)
        else:
            n, bad = ps5_to_pc(root, out, include_settings, log)
        z = None
        if zip_out:
            z = out + ".zip"
            if os.path.exists(z):
                z = unique(out) + ".zip"
            make_zip(out, z)
        log(t("Done: %d file(s) converted." % n, "Selesai: %d file dikonversi." % n))
        if bad:
            log(t("WARNING: %d file(s) FAILED (see '!' lines above). The result is INCOMPLETE - do NOT import it." % bad,
                  "PERINGATAN: %d file GAGAL (lihat baris '!' di atas). Hasil TIDAK LENGKAP - JANGAN diimpor." % bad))
        return out, z, to
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


# ----------------------------------------------------------------------------
# Self-test (known-answer test for the AES implementation)
# ----------------------------------------------------------------------------
def selftest():
    key = bytes(range(16))
    pt = bytes.fromhex("00112233445566778899aabbccddeeff")
    ct = bytes.fromhex("69c4e0d86a7b0430d8cdb78070b4c55a")  # FIPS-197 appendix C.1
    rk = _expand_key(key)
    assert _enc_block(rk, pt) == ct, "AES encrypt KAT failed"
    assert _dec_block(rk, ct) == pt, "AES decrypt KAT failed"
    for n in (0, 1, 15, 16, 17, 1000):
        d = os.urandom(n)
        k, iv = os.urandom(16), os.urandom(16)
        assert cbc_decrypt(k, iv, cbc_encrypt(k, iv, d)) == d
        assert pc_decrypt(pc_encrypt(d)) == d
    print("selftest OK")


# ----------------------------------------------------------------------------
# UI
# ----------------------------------------------------------------------------
def banner():
    print("=" * 60)
    print("  CotL Save Converter %s  -  Cult of the Lamb  PC <-> PS5" % __version__)
    print("=" * 60)
    print(t("  ALWAYS back up your saves before importing/overwriting anything.",
            "  SELALU backup save Anda sebelum mengimpor/menimpa apa pun."))
    print("")


def summary(out, z, to):
    print("")
    print(t("Output folder: ", "Folder hasil : ") + out)
    if z:
        print(t("Output zip   : ", "Zip hasil    : ") + z)
    print("")
    if to == "ps5":
        print(t("Next: import the result with your PS5 save manager (back up your PS5 save first).\n"
                "The PS5 game should be updated to the same or newer version than the PC save.",
                "Lanjut: impor hasilnya lewat save manager PS5 (backup save PS5 dulu).\n"
                "Game di PS5 sebaiknya versinya sama atau lebih baru dari save PC."))
    else:
        print(t("Next: copy the files into  %USERPROFILE%\\AppData\\LocalLow\\Massive Monster\\Cult Of The Lamb\\saves\n"
                "(back up the existing folder first, close the game before copying).\n"
                "The PC game should be the same or newer version than the PS5 save.",
                "Lanjut: salin file ke  %USERPROFILE%\\AppData\\LocalLow\\Massive Monster\\Cult Of The Lamb\\saves\n"
                "(backup folder lama dulu, tutup game sebelum menyalin).\n"
                "Game di PC sebaiknya versinya sama atau lebih baru dari save PS5."))


def interactive():
    global LANG
    banner()
    c = input("Language / Bahasa  [1] English   [2] Indonesia  : ").strip()
    LANG = "id" if c == "2" else "en"
    print("")
    src = clean_path(input(t("Drag & drop your save FOLDER or .ZIP here, then press Enter:\n> ",
                             "Seret FOLDER atau .ZIP save ke sini, lalu tekan Enter:\n> ")))
    tmp = tempfile.mkdtemp(prefix="cotlconv_")
    try:
        kind, _ = locate(prepare_input(src, tmp))
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    if kind is None:
        raise ConvError(t("No Cult of the Lamb save files found there.", "Tidak ada file save Cult of the Lamb di sana."))
    to = "ps5" if kind == "pc" else "pc"
    template = None
    if to == "ps5":
        print("")
        template = clean_path(input(t(
            "Optional: drag your existing PS5 save dump (folder/.zip from the save manager) to keep\n"
            "its sce_sys, or just press Enter to skip:\n> ",
            "Opsional: seret dump save PS5 Anda (folder/.zip dari save manager) agar sce_sys terjaga,\n"
            "atau langsung tekan Enter untuk lewati:\n> "))) or None
    inc = input(t("\nAlso convert settings (graphics/controls)? Usually NOT recommended. [y/N]: ",
                  "\nKonversi juga settings (grafis/kontrol)? Biasanya TIDAK disarankan. [y/N]: ")).strip().lower() == "y"
    print("")
    out, z, to = run(src, to=to, template=template, include_settings=inc)
    summary(out, z, to)


def main(argv=None):
    global LANG
    ap = argparse.ArgumentParser(description="Cult of the Lamb save converter (PC <-> PS5)")
    ap.add_argument("input", nargs="?", help="save folder or .zip (PC or PS5 dump); omit for interactive mode")
    ap.add_argument("--to", choices=["ps5", "pc"], help="target platform (default: auto-detect)")
    ap.add_argument("--template", help="PS5 dump (folder/.zip) to reuse sce_sys from (PC->PS5 only)")
    ap.add_argument("--out", help="output folder (default: next to the input)")
    ap.add_argument("--include-settings", action="store_true", help="also convert settings.json")
    ap.add_argument("--no-zip", action="store_true", help="do not create a .zip of the result")
    ap.add_argument("--lang", choices=["en", "id"], default=None)
    ap.add_argument("--no-pause", action="store_true", help="do not wait for Enter at the end")
    ap.add_argument("--selftest", action="store_true")
    ap.add_argument("--version", action="version", version=__version__)
    a = ap.parse_args(argv)
    if a.lang:
        LANG = a.lang
    if a.selftest:
        selftest()
        return 0
    pause = getattr(sys, "frozen", False) and not a.no_pause
    code = 0
    try:
        if a.input is None:
            interactive()
        else:
            banner()
            out, z, to = run(a.input, to=a.to, template=a.template, out=a.out,
                             include_settings=a.include_settings, zip_out=not a.no_zip)
            summary(out, z, to)
    except (ConvError, ValueError) as e:
        print("\nERROR: %s" % e)
        code = 1
    except (KeyboardInterrupt, EOFError):
        code = 1
    except Exception as e:  # keep the window open so the user can read it
        print("\nUNEXPECTED ERROR: %r" % e)
        code = 2
    if pause:
        try:
            input(t("\nPress Enter to exit...", "\nTekan Enter untuk keluar..."))
        except EOFError:
            pass
    return code


if __name__ == "__main__":
    sys.exit(main())
