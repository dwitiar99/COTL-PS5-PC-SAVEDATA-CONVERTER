# CotL Save Converter

Convert **Cult of the Lamb** saves between **PC** and **PS5** (PS5 dumps made with a save manager).
Portable, single file, works offline, nothing is uploaded anywhere.

*Konverter save **Cult of the Lamb** antara **PC** dan **PS5** (dump dari save manager). Portabel, satu file, offline.*

## How to use / Cara pakai

**EXE (easiest):** double-click `CotL-SaveConverter.exe`, then drag your save **folder or .zip** into the window and press Enter.
You can also drop a folder/zip directly onto the exe. The direction (PC→PS5 or PS5→PC) is detected automatically.

**Command line / Python:**

```
python cotl_converter.py <folder-or-zip>                         # auto-detect direction
python cotl_converter.py pc_saves --template ps5_dump.zip        # PC -> PS5, keep your PS5 sce_sys
python cotl_converter.py ps5_dump.zip --to pc                    # PS5 -> PC
```

Options: `--out DIR`, `--include-settings`, `--no-zip`, `--lang en|id`, `--selftest`.

### Where are the saves?

* **PC:** `%USERPROFILE%\AppData\LocalLow\Massive Monster\Cult Of The Lamb\saves`
  (`slot_0.mp`, `meta_0.mp`, `persistence.json`, `settings.json`)
* **PS5:** the dump from your save manager - folders `sdimg_slot-0mp`, `sdimg_meta-0mp`, `sdimg_persistence`, ...

### PC → PS5: give it a PS5 template (recommended)

The PS5 side needs the console-specific `sce_sys` folders (param.sfo, keystone, icon). They cannot be created by a converter.
Pass **your own PS5 dump** (from a game you already launched once) as the template (`--template`, or drag it in when asked).
The tool copies it and only replaces the `data` files, so `sce_sys` stays intact. Then import the result with your save manager.

### PS5 → PC

Copy the resulting files into the PC `saves` folder (close the game first). `prefs` is PS5-only and is ignored.

## Important

* **Back up everything first** (both platforms). A wrong save can't be recovered.
* **Game version:** the target game should be the **same or newer** version than the save. The tool prints the save's game
  version and warns if a PC save is newer than the PS5 save in your template. Update the game first.
* `settings` (graphics/controls) is platform-specific and **skipped by default** (`--include-settings` to convert it).
* Only the first save slot (`slot_0`) was verified. Other slots use the same naming pattern (`slot_1.mp` ↔ `sdimg_slot-1mp`)
  but that is an assumption.
* Antivirus programs sometimes flag PyInstaller `.exe` files (false positive). If you distribute the exe, also publish the source
  and the SHA-256 checksum, or build it yourself with `build_exe.bat`.

## Status

* **PC → PS5:** verified on a real PS5 (jailbroken, save manager import) - save loaded and ran normally.
* **PS5 → PC:** tested by round-trip (decrypted content is byte-identical to the original PC save), but not on a real PC game install yet.
  Please report results.
* The AES implementation is checked against the FIPS-197 test vector and against a reference library;
  re-encrypting the original PC files with their own key/IV reproduces them byte for byte.

## How it works

PC files: `0x45 | key(16) | iv(16) | AES-128-CBC ciphertext`. Decrypted, `slot`/`meta` are MessagePack (the slot is LZ4-compressed) and
`persistence`/`settings` are JSON. PS5 files are the same payloads, unencrypted, with a 2-byte header:
`MP` + MessagePack, or `ZB` + gzip(JSON with BOM). The converter only decrypts/encrypts and re-wraps; it never edits save contents.

## Build the exe yourself

* **Windows:** run `build_exe.bat` (needs Python 3.9+). Result: `dist\CotL-SaveConverter.exe`.
* **GitHub:** push this folder to a repo, then *Actions → Build Windows exe → Run workflow*, and download the artifact.

## Credits / Disclaimer

The PC encryption layout is documented by Matteo Fattorini's [cotl-save-editor](https://github.com/Matteo-Fattorini/cotl-save-editor) (MIT).
This is an independent implementation, not affiliated with Massive Monster or Devolver Digital. Use at your own risk.
