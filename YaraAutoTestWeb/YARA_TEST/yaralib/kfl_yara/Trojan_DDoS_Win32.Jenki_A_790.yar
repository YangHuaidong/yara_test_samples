rule Trojan_DDoS_Win32_Jenki_A_790
{
	meta:
		judge = "black"
		threatname = "Trojan[DDoS]/Win32.Jenki.A"
		threattype = "DDoS"
		family = "Jenki"
		hacker = "None"
		refer = "eaf441fb039b2224d89d10e3adb46ff9"
		author = "HuangYY"
		comment = "None"
		date = "2017-09-19"
		description = "None"
	strings:		
		$s0 = "notpad.pdb"
		$s1 = "xpxxxx"
		$s3 = "https://"
		$s4 = "http://"
		$s5 = "frexp"
		$s6 = "fmod"
		$s7 = "_hypot"
		$s8 = "floor"
		$s9 = "sqrt"
	condition:
		all of them
}