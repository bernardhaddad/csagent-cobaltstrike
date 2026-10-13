import "pe"

rule CS_Loader_Goopdate_Sideload_CsAgent_Campaign
{
    meta:
        description = "MinGW-built goopdate.dll sideloaded by DropboxUpdate.exe from ISO; drops decoy win.dll as %TEMP%\\cam_numbers_*.pdf and carries an embedded raw Beacon"
        author = "Bernard Haddad"
        status = "experimental"
        date = "2026-10-13"
        reference_sha256 = "91fc3bf4caf5d6014b1f344b865ab1e063d6a7e9acf5705ad7ced4df91620771"
    strings:
        $beacon = "rawbeacon.dll" ascii
        $decoy1 = "cam_numbers_" ascii wide
        $decoy2 = "win.dll" ascii wide
        $mingw = "Mingw-w64 runtime failure" ascii
        $blob = "AQAAAMAAAAA" ascii
    condition:
        pe.is_dll() and pe.exports("DllEntry") and
        pe.imports("SHELL32.dll", "ShellExecuteExW") and pe.imports("KERNEL32.dll", "GetTempPathW") and
        $beacon and 1 of ($decoy*) and ($mingw or $blob)
}

rule ISO_DropboxUpdate_Volume_Goopdate_Sideload
{
    meta:
        description = "ISO with volume label DropboxUpdate carrying goopdate.dll and a decoy win.dll"
        author = "Bernard Haddad"
        status = "experimental"
        date = "2026-10-13"
    strings:
        $vol = "DropboxUpdate" ascii
        $f1 = "GOOPDATE.DLL" ascii nocase
        $f2 = "WIN.DLL" ascii nocase
        $cd = "CD001" ascii
    condition:
        $cd at 0x8001 and $vol in (0x8000..0x8100) and $f1 and $f2
}
