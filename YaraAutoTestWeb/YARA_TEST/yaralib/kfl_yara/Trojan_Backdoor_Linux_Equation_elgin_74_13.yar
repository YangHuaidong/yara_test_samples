rule Trojan_Backdoor_Linux_Equation_elgin_74_13
{
    meta:
        judge = "black"
        threatname = "Trojan[Backdoor]/Linux.Equation.elgin"
        threattype = "Backdoor"
        family = "Equation"
        hacker = "None"
        author = "Florian Roth-copy"
        refer = "25f16522e095f3e516b330bf96ba16e0"
        comment = "APT Equation Grou-https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
        date = "2018-07-09"
        description = "Equation Group hack tool leaked by ShadowBrokers- file elgingamble"
	strings:
		$x1 = "* * * * * root chown root %s; chmod 4755 %s; %s" fullword ascii
		$x2 = "[-] kernel not vulnerable" fullword ascii
		$x3 = "[-] failed to spawn shell: %s" fullword ascii
		$x4 = "-s shell           Use shell instead of %s" fullword ascii
	condition:
		1 of them
}