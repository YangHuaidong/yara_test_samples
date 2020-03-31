rule Trojan_Ransom_Win32_Petya_20170811104331_965 
{
	meta:
		judge = "black"
		threatname = "Trojan[Ransomware]/Win32.Petya"
		threattype = "Ransomware"
		family = "Petya"
		hacker = "None"
		refer = "71b6a493388e7d0b40c83ce903bc6b04"
		description = "None"
		comment = "None"
		author = "None"
		date = "2017-07-14"
	strings:
		$s0 = "\\\\.\\PhysicalDriv0"
		$s1 = "1Mz7153HMuxXTuR2R1t78mGSdzaAtNbBWX" fullword nocase wide ascii
		$s2 = "medd0156723,U"
		$s3 = ">q.df1"
		$s4 = "255.255.255.255"
		$s5 = "*F2\\a1wsHp"

	condition:
		all of them
}
