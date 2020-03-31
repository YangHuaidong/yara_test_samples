rule Trojan_DDoS_Win32_Nitol_F_1098
{
	meta:
		judge = "black"
		threatname = "Trojan[DDoS]/Win32.Nitol.F"
		threattype = "DDoS"
		family = "Nitol"
		hacker = "None"
		refer = "0a4b0629ba246f5d634db0fd138d3950"
		author = "lizhenling"
		comment = "None"
		date = "2019-04-11"
		description = "None"

	strings:		
		$s0 = "PostThreadMessageA"
		$s1 = "key=%s"
		$s2 = "TCPConnectFloodThread.target = %s"
		$s3 = "cmd /c %s"
		$s4 = "LockServiceDatabase"
		$s5 = "X-%c: %c"
		$s6 = "OpenSCManagerA"

	condition:
		5 of them
}