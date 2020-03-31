rule Trojan_Downloader_Win32_Triton_e_1048 {
    meta:
        judge = "black"
		threatname = "Trojan[Downloader]/Win32.Triton.e"
		threattype = "Downloader"
		family = "Triton"
		hacker = "none"
		comment = "None"
		date = "2019-02-19"
		author = "mqx"
		description = "Matches the known samples of the HatMan malware,Trilog.exe" 
		refer = "6C39C3F4A08D3D78F2EB973A94BD7718"
    strings:
        $nullsub = { ff ff 60 38  02 00 00 44 20 00 80 4e }
        $preset = { 80 00 40 3c  00 00 62 80  40 00 80 3c  40 20 03 7c ?? ?? 82 40 04 00 62 80 60 00 80 3c 40 20 03 7c ?? ?? 82 40 ?? ?? 42 38}
        $div1 = { 9a 78 56 00 }
        $div2 = { 34 12 00 00 }
    condition:
        $nullsub and $preset and $div1 and $div2 and filesize < 100KB
}