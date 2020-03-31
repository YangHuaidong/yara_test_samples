rule Trojan_DDoS_Win32_Palevo_02_20180611103221_941 
{
	meta:
		judge = "black"
		threatname = "Trojan[DDOS]/Win32.Palevo"
		threattype = "DDOS"
		family = "Palevo"
		hacker = "None"
		refer = "2cc1bc90c1a08fa6c3069a4a4fdff6f2"
		description = "None"
		comment = "None"
		author = "Lizhenling"
		date = "2018-06-06"
	strings:
		$s0 = "gs/wKo"
		$s1 = "SetFilePointerEx"
		$s2 = "PathRemoveFileSpecA"
		$s3 = "EncodePointer"
		$s4 = "WaitForSingleObject"

	condition:
		all of them
}
