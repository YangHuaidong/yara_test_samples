rule Trojan_Backdoor_Win32_IronGate_NetResView_1088
{
	meta:
		judge = "black"
		threatname = "Trojan[Backdoor]/Win32.IronGate.NetResView"
		threattype = "ICS,Backdoor"
		family = "IronGate"
		hacker = "None"
		refer = "7a0c1017e6b5bb5dc776b3b883a1d0e0"
		author = "LiuGuangzhu"
		comment = "None"
		date = "2019-03-21"
		description = "https://github.com/Neo23x0/signature-base/blob/master/yara/apt_irongate.yar"
	strings:
		$s1 = "NetResView.exe" fullword wide
		$s2 = "2005 - 2013 Nir Sofer" wide
	condition:
		uint16(0) == 0x5a4d and filesize < 100KB and all of them
}