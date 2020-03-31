rule Trojan_Backdoor_Linux_Equation_ebbsha_72_11
{
    meta:
        judge = "black"
        threatname = "Trojan[Backdoor]/Linux.Equation.ebbsha"
        threattype = "Backdoor"
        family = "Equation"
        hacker = "None"
        author = "Florian Roth-copy"
        refer = "55dae80f0414e67e86fb5edf393c566c"
        comment = "APT Equation Grou-https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
        date = "2018-07-09"
        description = "Equation Group hack tool leaked by ShadowBrokers- file ebbshave.v5"
	strings:
		$s1 = "executing ./ebbnew_linux -r %s -v %s -A %s %s -t %s -p %s" fullword ascii
		$s2 = "./ebbnew_linux.wrapper -o 2 -v 2 -t 192.168.10.4 -p 32772" fullword ascii
		$s3 = "version 1 - Start with option #18 first, if it fails then try this option" fullword ascii
		$s4 = "%s is a wrapper program for ebbnew_linux exploit for Sparc Solaris RPC services" fullword ascii
	condition:
		( uint16(0) == 0x457f and filesize < 20KB and 1 of them ) or ( 2 of them )
}