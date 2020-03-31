rule Trojan_Backdoor_Linux_Equation_libexp_75_15
{
    meta:
        judge = "black"
        threatname = "Trojan[Backdoor]/Linux.Equation.libexp"
        threattype = "Backdoor"
        family = "Equation"
        hacker = "None"
        author = "Florian Roth-copy"
        refer = "652336dacf734174510dd7f2f77a4a9e"
        comment = "APT Equation Grou-https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
        date = "2018-07-09"
        description = "Equation Group hack tool leaked by ShadowBrokers- file libXmexploit2.8"
	strings:
		$s1 = "Usage: ./exp command display_to_return_to" fullword ascii
		$s2 = "sizeof shellcode = %d" fullword ascii
		$s3 = "Execve failed!" fullword ascii
	condition:
		( uint16(0) == 0x457f and filesize < 40KB and 1 of them )
}