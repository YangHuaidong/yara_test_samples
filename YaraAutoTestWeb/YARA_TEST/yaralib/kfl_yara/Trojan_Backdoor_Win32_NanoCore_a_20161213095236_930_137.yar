rule Trojan_Backdoor_Win32_NanoCore_a_20161213095236_930_137 
{
	meta:
		judge = "black"
		threatname = "Trojan[Backdoor]/Win32.NanoCore.a"
		threattype = "rat"
		family = "NanoCore"
		hacker = "None"
		refer = "877b44301aefc35bfa1ce11f65e0f36c"
		description = "None"
		comment = "None"
		author = "Kevin Breen <kevin@techanarchy.net>"
		date = "2016-06-23"
	strings:
		$s0 = "NanoCore"
		$s1 = "ClientPlugin"
		$s2 = "ProjectData"
		$s3 = "DESCrypto"
		$s4 = "KeepAlive"
		$s5 = "IPNETROW"
		$s6 = "LogClientMessage"
		$s7 = "|ClientHost"
		$s8 = "get_Connected"
		$s9 = "#=q"
		$s10 = { 43 6f 24 cb 95 30 38 39 }

	condition:
		6 of them
}
