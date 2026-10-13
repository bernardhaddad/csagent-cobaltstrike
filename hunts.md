# Cobalt Strike posing as CrowdStrike: hunts

Signed Cobalt Strike sideloaded by a real DropboxUpdate.exe out of an ISO, beaconing to Azure
with Falcon-looking traffic. IOCs in `iocs.csv`. Queries are Falcon LogScale / NG-SIEM (CQL)
using standard Falcon event names; check field names on your tenant before scheduling.

## 1. Straight IOC sweep

```
#event_simpleName=DnsRequest
| DomainName=/asiioasdjasiojasodijasa\.eastus\.cloudapp\.azure\.com/i
| groupBy([ComputerName, ContextBaseFileName], function=[count(), min(@timestamp), max(@timestamp)])
```

```
#event_simpleName=NetworkConnectIP4 RemoteAddressIP4=20.51.202.31
| groupBy([ComputerName, ContextBaseFileName, RemotePort], function=count())
```

```
// all campaign files except the legit DropboxUpdate.exe (see hunt 2 for that one)
in(field="SHA256HashData", values=[
 "3e0273d0b3ada87e117da1c421aac04cd2b8aca20a83ba31502bb252363fa44a",
 "d56389a4c397dc001b121945831cf17cb69e33a7e926e29ccf0bd6623d8c9a3b",
 "6b494da43c3beee0845521cd67f3859ac419f6da6e4497cb00cbcca7faf184e8",
 "99093da361974b6920579cd56c210e79da9dc9ca92fa345d192fc1ee52ae096b",
 "4401c11cb33030a96570433bab9fd48619c6fbaefb783b12388401a861761d9a",
 "54d95a19a2ce05b1d8c66c21f2863658960f609fa809cdce43b6a0192a8eda6e",
 "763ac38c6373a4d5bd820b904e934c459e57bee6016b5325368a45f7f5b8753e",
 "6a6b881ebf7bf387ac106bc20addd9f84e2df1c244d7b05f97f3b3e152aefda5",
 "81883bede526e686d7739be06ae32c73f78058a1603f1756c3263162452793f8",
 "43692ee377d363a4db702fcbd1fdf9f160e708faab66a62347b5446c00fa1000",
 "50d674ab3d7f1fd98e436cf7d324ddb79ab0386911d1c47b3323190bf4d3a54e",
 "2fe66bca36b205525244d27fd040f2c894ecaafcf84d25d0865451b5d25266c8",
 "91fc3bf4caf5d6014b1f344b865ab1e063d6a7e9acf5705ad7ced4df91620771",
 "6bd9e8b490500dadea8c5657cdc19fd15829730b7fde1a17b5f8e89f132f893e",
 "1bfaef301a9abe51f4a427522818bb2481271e1ce4406a407b2c27a1c2184e08",
 "9332cd1b348c95e0a97ac66011333de956f075e260fc971a849a108c489ab763",
 "0c42e0b364ec7d922c00fa43c308a97b044f93ca9d12720bdc1b1b691a5dabe0",
 "11bd47b08e40ece5986f45319fcb6b4bf16855fb376d0407fd8274ede1a5c57f",
 "c047295e930fd702785c3e7519bd3e515d1cf9964db868599b81dd29643635a5",
 "7d23213dc26b048ea2ad2f8359fadbe35c97b844012759bd0915b31d387638b2",
 "400eb8c3a2e40cbbeb437d2b67c9f37687cb1327c595bc112979292c28f6376e",
 "19427b8b6f4fccdb15c7ba4a8aaed1e3e0f1476537cfa7ce15ddaac3004e8cba",
 "4ed40c2e0703f328bd10acea6b87cdc22737e30e85e8f438f1e93a0c46371a53",
 "6e4ca598bf2e8f23281e611f3cea05c9b55766b1909b16cfc72e3b763fed6af4",
 "3a849c16c3e9ffc90db8fe61de2a7a8c5f8cb3fb61bef48d6285ab467c4fdd42"])
| groupBy([ComputerName, #event_simpleName, ImageFileName, SHA256HashData], function=count())
```

Also worth adding the domain and hashes as custom IOCs (Detect) in IOC Management.

## 2. DropboxUpdate.exe outside Dropbox (the sideload host)

Same Dropbox-signed DropboxUpdate.exe (7655221b...) in every ISO so far, renamed to
`*-pdf.exe` / statement names. The hash is legit, so key on where it runs.

```
#event_simpleName=ProcessRollup2
| SHA256HashData="7655221b493047c61285e1de78807d0584920b0d14d150e2487da9728b1926f3"
  or ImageFileName=/\\DropboxUpdate\.exe$/i
| ImageFileName!=/\\Dropbox\\(Update|Client)\\/i
| table([@timestamp, ComputerName, UserName, ImageFileName, CommandLine, ParentBaseFileName])
```

## 3. Anything executed from a mounted ISO that looks like a document

```
#event_simpleName=ProcessRollup2
| ImageFileName=/\\Device\\CdRom\d+\\/i
| ImageFileName=/(statement|invoice|pdf|document|compensation|ssa)/i
| table([@timestamp, ComputerName, UserName, ImageFileName, ParentBaseFileName, SHA256HashData])
```

## 4. goopdate.dll loaded from somewhere it shouldn't be

Legit goopdate.dll lives under Google / Dropbox update folders.

```
#event_simpleName=ClassifiedModuleLoad
| ImageFileName=/\\goopdate\.dll$/i
| ImageFileName!=/\\(Google|Dropbox)\\Update\\/i
| groupBy([ComputerName, ImageFileName, SHA256HashData], function=count())
```

## 5. Decoy PDF drop

```
#event_simpleName=/^(PdfFileWritten|NewExecutableWritten|GenericFileWritten)$/
| TargetFileName=/\\Temp\\cam_numbers_[0-9a-f]+\.pdf$/i
| table([@timestamp, ComputerName, TargetFileName, ContextBaseFileName])
```

## 6. Beacon spawn_to

`msiexec.exe -Embedding` is normally started by msiexec.exe (the installer service).

```
#event_simpleName=ProcessRollup2
| ImageFileName=/\\(sysnative|system32|syswow64)\\msiexec\.exe$/i CommandLine=/-Embedding/i
| ParentBaseFileName!=/^msiexec\.exe$/i
| groupBy([ComputerName, ParentBaseFileName, CommandLine], function=count())
```

## 7. Fake Falcon traffic (proxy / firewall logs, not endpoint)

Falcon telemetry won't show the HTTPS user agent. In proxy logs, look for:

- user agent containing `CsAgent` going to anything that isn't CrowdStrike's cloud
- URI path starting `/api/v2/crowdstrike/`
- cookie `falcon_session=` or headers `X-CS-AGENTID` / `X-CS-VERSION`
- any destination `*.cloudapp.azure.com` from workstations (worth a baseline anyway)

## Notes

- Lure themes so far: US "SSA-Statement-<date>-<time>.iso" (from 11 Sep), then UK GOV.UK
  "compensation-recovery-statement-<n>.iso" (Oct).
- Signer names rotate; each cert is valid for 3 days (Ashley Marie Boynton alone had three
  certs on 2, 3 and 4 Oct). Issuers seen: "Microsoft ID Verified CS AOC CA 03", "AOC CA 04"
  and "EOC CA 04". Treat files signed by an individual's name through those CAs, arriving
  in an ISO, as suspect. Thumbprints are in iocs.csv.
- All 5 ISOs contain the same DropboxUpdate.exe (7655221b...) and goopdate.dll; the 4 October
  ISOs share the same decoy PDF (f0ac088b...).
- C2 DNS first seen 27 Aug 2026, about two weeks before the first sample.
- 20.51.202.31 resolved to an unrelated site in 2020; it's shared Azure space, so don't
  block-and-forget on the IP alone.
