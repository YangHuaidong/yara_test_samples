rule Trojan_Backdoor_Win32_Passup_pass_739
{
	meta:
		judge = "black"
		threatname = "Trojan[Backdoor]/Win32.Passup.pass"
		threattype = "Backdoor"
		family = "Passup"
		hacker = "None"
		refer = "05367b6e911d2a1d934bed7807a405e8"
		author = "HuangYY"
		comment = "None"
		date = "2017-11-02"
		description = "None"

	strings:		
		$s0 = "laZagne.exe.manifest"
		$s1 = "bwin32wnet.pyd"
		$s2 = "opyi-windows-manifest-filename"
		$s3 = "bunicodedata.pyd"
		$s4 = "bselect.pyd"
		$s5 = "bpyexpat.pyd"
		$s6 = "bpsutil._psutil_windows.pyd"
	condition:
		5 of them
}