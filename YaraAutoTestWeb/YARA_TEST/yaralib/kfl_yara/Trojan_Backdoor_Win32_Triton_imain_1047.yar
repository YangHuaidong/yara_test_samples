rule Trojan_Backdoor_Win32_Triton_imain_1047 {
    meta:
        judge = "black"
		threatname = "Trojan[Backdoor]/Win32.Triton.e"
		threattype = "Backdoor"
		family = "Triton"
		hacker = "none"
		comment = "None"
		date = "2019-02-20"
		author = "mqx"
		description = "Matches the known samples of the HatMan malware" 
        refer = "437F135BA179959A580412E564D3107F"
    strings:
        $memcpy_be  = { 7c a9 03 a6  38 84 ff ff 38 63 ff ff 8c a4 00 01 9c a3 00 01  42 00 ff f8 4e 80 00 20}
        $memcpy_le  = { a6 03 a9 7c ff ff 84 38 ff ff 63 38 01 00 a4 8c 01 00 a3 9c f8 ff 00 42 20 00 80 4e}
        $ocode_be   = { 3c 00 00 03  60 00 a0 b0  7c 09 03 a6  4e 80 04 20 }
        $ocode_le   = { 03 00 00 3c  b0 a0 00 60  a6 03 09 7c  20 04 80 4e }
        $mfmsr_be   = { 7c 63 00 a6 }
        $mfmsr_le   = { a6 00 63 7c }
        $mtmsr_be   = { 7c 63 01 24 }
        $mtmsr_le   = { 24 01 63 7c }

    condition:
        ($memcpy_be or $memcpy_le) and ($ocode_be or $ocode_le) and (($mfmsr_be and $mtmsr_be) or ($mfmsr_le and $mtmsr_le))
}