rule Trojan_Backdoor_Win32_Triton_a_1157
{
	meta:
		judge = "black"
		threatname = "Trojan[Backdoor]/Win32.Triton.a"
		threattype = "ICS,Backdoor"
		family = "Triton"
		hacker = "None"
		refer = "8b675db417cc8b23f4c43f3de5c83438"
		author = "LiuGuangzhu"
		comment = "None"
		date = "2019-04-22"
		description = "None"
	strings:
        $s0 = "sh.pycs" ascii wide
        $s1 = "isinstancet" ascii wide
		$s2 = "basestringt" ascii wide
		$s3 = "sh.pyct" ascii wide
		$s4 = "unpackt" ascii wide
	condition:
		all of them
}