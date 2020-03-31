rule Trojan_Backdoor_Win32_IronGate_PyInstaller_1089
{
	meta:
		judge = "black"
		threatname = "Trojan[Backdoor]/Win32.IronGate.PyInstaller"
		threattype = "ICS,Backdoor"
		family = "IronGate"
		hacker = "None"
		refer = "75d118996f5190edafca1b1904a7eea8"
		author = "LiuGuangzhu"
		comment = "None"
		date = "2019-03-21"
		description = "https://github.com/Neo23x0/signature-base/blob/master/yara/apt_irongate.yar"
	strings:
		$s1 = "bpython27.dll" fullword ascii
		$s5 = "%s%s.exe" fullword ascii
		$s6 = "bupdate.exe.manifest" fullword ascii
		$s9 = "bunicodedata.pyd" fullword ascii
		$s11 = "distutils.sysconfig(" fullword ascii
		$s16 = "distutils.debug(" fullword ascii
		$s18 = "supdate" fullword ascii
	condition:
		uint16(0) == 0x5a4d and all of them
}