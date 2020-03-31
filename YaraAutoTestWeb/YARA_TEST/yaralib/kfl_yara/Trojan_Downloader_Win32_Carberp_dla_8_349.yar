rule Trojan_Downloader_Win32_Carberp_dla_8_349 
{

    meta:
        judge = "black"
				threatname = "Trojan[Downloader]/Win32.Carberp.dla"
				threattype = "Downloader"
				family = "Carberp"
				hacker = "None"
				comment = "MISP 3971 Furtim_nativeDLL"
				date = "2016-06-13"
				author = "Florian Roth-DC"
				description = "Detects Furtim malware - file native.dll" 
				refer = "5f56c54983e1ea1f8e06c29e796bcf25"

    strings:
        $s1 = "FqkVpTvBwTrhPFjfFF6ZQRK44hHl26" fullword ascii
        $op0 = { e0 b3 42 00 c7 84 24 ac } /* Opcode */
        $op1 = { a1 e0 79 44 00 56 ff 90 10 01 00 00 a1 e0 79 44 } /* Opcode */
        $op2 = { bf d0 25 44 00 57 89 4d f0 ff 90 d4 02 00 00 59 } /* Opcode */
    condition:
        uint16(0) == 0x5a4d and filesize < 900KB and $s1 or all of ($op*)
}
