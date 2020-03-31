rule Trojan_DDoS_Win32_Generic_hz_20170619115502_1006_298 
{
	meta:
		judge = "black"
		threatname = "Trojan[DDoS]/Win32.Generic.hz"
		threattype = "DDOS"
		family = "Generic"
		hacker = "none"
		refer = "9686b8ba92f7c79a9aa58bb50bdeca0b"
		description = "None"
		comment = "none"
		author = "xc"
		date = "2017-06-12"
	strings:
		$s0 = "hz32\\x.bat"
		$s1 = "hz32\\520.vbs"
		$s2 = "hz32\\hz32.exe"

	condition:
		all of them
}
