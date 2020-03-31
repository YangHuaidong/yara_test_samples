rule Trojan_DDoS_Win32_IPK_A_20171221111939_926 
{
	meta:
		judge = "black"
		threatname = "Trojan[DDoS]/Win32.IPK.A"
		threattype = "DDOS"
		family = "IPK"
		hacker = "None"
		refer = "a571607348efcb32802c1e40ff7dc139"
		description = "None"
		comment = "None"
		author = "HuangYY"
		date = "2017-07-06"
	strings:
		$s0 = "MPMutex"
		$s1 = "AdobeART"
		$s3 = "encpassword"
		$s4 = "Microsoft\\WinNT.tmp"
		$s5 = "IPKPMTX"
		$s6 = "TServer"
		$s7 = "TMPSocket"

	condition:
		all of them
}
