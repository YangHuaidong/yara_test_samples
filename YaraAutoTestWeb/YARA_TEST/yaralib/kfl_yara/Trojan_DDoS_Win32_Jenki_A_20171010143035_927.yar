rule Trojan_DDoS_Win32_Jenki_A_20171010143035_927 
{
	meta:
		judge = "black"
		threatname = "Trojan[DDoS]/Win32.Jenki.A"
		threattype = "DDOS"
		family = "Jenki"
		hacker = "None"
		refer = "eaf441fb039b2224d89d10e3adb46ff9"
		description = "None"
		comment = "None"
		author = "HuangYY"
		date = "2017-09-19"
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
