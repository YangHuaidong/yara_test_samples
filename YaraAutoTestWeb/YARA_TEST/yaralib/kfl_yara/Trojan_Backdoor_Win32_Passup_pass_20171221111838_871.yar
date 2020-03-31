rule Trojan_Backdoor_Win32_Passup_pass_20171221111838_871 
{
	meta:
		judge = "black"
		threatname = "Trojan[Backdoor]/Win32.Passup.pass"
		threattype = "BackDoor"
		family = "Passup"
		hacker = "None"
		refer = "05367b6e911d2a1d934bed7807a405e8"
		description = "None"
		comment = "None"
		author = "HuangYY"
		date = "2017-11-02"
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
