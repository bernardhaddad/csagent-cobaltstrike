# csagent-cobaltstrike

Notes on a Cobalt Strike campaign that dresses its C2 traffic up as the CrowdStrike sensor.
Running since at least September 2026.

## The chain

An ISO (volume label `DropboxUpdate`) with three files:

- `compensation-recovery-statement-pdf.exe` - the real DropboxUpdate.exe 1.3.537.5, signed
  by Dropbox. Built on Google's Omaha updater, so it loads `goopdate.dll` from its own
  folder and calls `DllEntry`.
- `goopdate.dll` - the loader. MinGW build, exports only `DllEntry`, signed through
  Microsoft's code signing service with a 3 day cert in a person's name.
- `win.dll` - not a DLL, a PDF. GOV.UK logo, "Secure File Access", update Acrobat.

The loader copies `win.dll` to `%TEMP%\cam_numbers_<x>.pdf` and opens it (the name is fixed
per build), then decrypts the beacon it carries.

Earlier ISOs were named `SSA-Statement-<date>-<time>.iso`, later ones
`compensation-recovery-statement-<n>.iso`. Every one so far has the same DropboxUpdate.exe.

## The beacon

The loader holds a base64 blob: 16 byte header, 192 byte key, then the beacon XORed with
that key. The beacon has `MZ` swapped for `AIBJ`, `PE` for `CS` and obfuscated section
names. Config is the usual XOR 0x2e, but the entries are shuffled, which is why older
parsers stop after a couple of fields. `extract_beacon_config.py` walks it statically.

What's in it (`beacon_config_91fc3bf4.json`):

```
C2              asiioasdjasiojasodijasa.eastus.cloudapp.azure.com:443
GET             /api/v2/crowdstrike/entities/sensor-update-policy/v2
POST            /api/v2/crowdstrike/entities/detections/v2
User-Agent      CrowdStrike CsAgent/7.04.18110.0 (Windows 10.0.19045; x64)
Headers         X-CS-AGENTID: a3f7c2e18b4d4f6a9e2c1d5f8a7b3e9c, X-CS-VERSION: 7.04.18110.0
Cookie          falcon_session=
POST fields     DetectionSummary, status, severity_low, detection_id ...
Sleep           60s, 25% jitter
spawn_to        %windir%\sysnative\msiexec.exe -Embedding (x86: syswow64)
Watermark       1817228496
PubKey sha256   14e5aca1e0aaf70951e22fc12b78705565675437d4d9d95eabd9327b1fe40001
```

Nothing in the config goes after the sensor. The CrowdStrike name is there for the proxy
logs.

## Certs

Four names, six certs so far, each valid 3 days. Issuers seen: Microsoft ID Verified CS AOC
CA 03, AOC CA 04 and EOC CA 04. Three of the six were already revoked when I checked.
Thumbprints are in `iocs.csv`.

In the sample I took apart, the DLL compile time, the signing time and the ISO creation
time are all 2026-10-13 13:44 UTC. Build, sign and package are automated.

## Files

- `iocs.csv` - domain, IP, cert thumbprints, ISOs, loaders, decoy hashes, with confidence and
  what each one rests on. Don't block the DropboxUpdate.exe hash, it's the real Dropbox file.
- `hunts.md` - Falcon LogScale / NG-SIEM queries plus proxy log ideas
- `goopdate_cs_loader.yar` - YARA for the loader and the ISO
- `extract_beacon_config.py` - static config extractor (`python -I extract_beacon_config.py goopdate.dll`)

The YARA and the queries are experimental. The YARA matches the loader and the ISO here and
not the Dropbox EXE or the decoy, but I haven't run it over a clean set or the other loaders
yet.
Check the queries' field names on your tenant before scheduling them.

No samples in here.

YARA and hunts: DRL 1.1. Code: MIT.
