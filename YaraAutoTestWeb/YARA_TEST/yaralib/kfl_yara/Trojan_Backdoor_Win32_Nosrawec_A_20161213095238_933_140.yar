rule Trojan_Backdoor_Win32_Nosrawec_A_20161213095238_933_140 
{
	meta:
		judge = "black"
		threatname = "Trojan[Backdoor]/Win32.Nosrawec.A"
		threattype = "rat"
		family = "Nosrawec"
		hacker = "None"
		refer = "0025a085cb30c8b1acd511a38d598fdf"
		description = "Xena"
		comment = "None"
		author = "Kevin Breen <kevin@techanarchy.net>"
		date = "2016-06-23"
	strings:
		$s0 = "HuntHTTPDownload"
		$s1 = "KuInstallation"
		$s2 = "PcnRawinput"
		$s3 = "untCMDList"
		$s4 = "%uWebcam"
		$s5 = "KACMConvertor"
		$s6 = "$VarUtils"
		$s7 = "****##"

	condition:
		all of them
}
