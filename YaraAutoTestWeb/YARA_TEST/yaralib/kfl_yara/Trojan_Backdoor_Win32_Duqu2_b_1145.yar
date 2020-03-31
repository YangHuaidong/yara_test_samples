rule Trojan_Backdoor_Win32_Duqu2_b_1145
{
	meta:
		judge = "black"
		threatname = "Trojan[Backdoor]/Win32.Duqu2.b"
		threattype = "ICS,Backdoor"
		family = "Duqu2"
		hacker = "None"
		refer = "e8d6b4dadb96ddb58775e6c85b10b6cc"
		author = "LiuGuangzhu"
		comment = "None"
		date = "2019-04-28"
		description = "None"
    strings:
		$s0 = {72 73 34 99 71 98 2B 72 73 34 99 71 98 2B}
    condition:
		#s0 > 400
}