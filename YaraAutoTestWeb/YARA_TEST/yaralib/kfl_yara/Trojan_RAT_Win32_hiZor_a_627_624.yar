
rule Trojan_RAT_Win32_hiZor_a_627_624
{
	meta:
	judge = "black"
    threatname = "Trojan[RAT]/Win32.hiZor.a"
    threattype = "RAT"
    family = "hiZor"
    hacker = "None"
    author = "lz"
    refer = "75d3d1f23628122a64a2f1b7ef33f5cf,d9821468315ccd3b9ea03161566ef18e,b9af5f5fd434a65d7aa1b55f5441c90a"
    comment = "None"
    date = "2018-07-30"
    description = "None"
    description = "Detects hiZor RAT"
	
	strings:
		// Part of the encoded User-Agent = Mozilla
		$s1 = { c7 [5] 40 00 62 00 c7 [5] 77 00 64 00 c7 [5] 61 00 61 00 c7 [5] 6c 00 }

		// XOR to decode User-Agent after string stacking 0x10001630
		$s2 = { 66 [7] 0d 40 83 ?? ?? 7c ?? }

		// XOR with 0x2E - 0x10002EF6
		$s3 = { 80 [2] 2e 40 3b ?? 72 ?? }

		$s4 = "CmdProcessExited" wide ascii
		$s5 = "rootDir" wide ascii
		$s6 = "DllRegisterServer" wide ascii
		$s7 = "GetNativeSystemInfo" wide ascii
		$s8 = "%08x%08x%08x%08x" wide ascii
	condition:
		(uint16(0) == 0x5A4D or uint32(0) == 0x4464c457f) and (all of them)
}
