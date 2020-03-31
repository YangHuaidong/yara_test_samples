rule Trojan_Backdoor_Linux_Equation_evolv_369_14
{
    meta:
        judge = "black"
        threatname = "Trojan[Backdoor]/Linux.Equation.evolv"
        threattype = "Backdoor"
        family = "Equation"
        hacker = "None"
        author = "Florian Roth-copy"
        refer = "e64fff91cfae71cfa6411fa8af85a4b3"
        comment = "APT Equation Grou-https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
        date = "2018-07-02"
        description = "Equation Group hack tool leaked by ShadowBrokers- evolvingstrategy.1.0.1.1"
	strings:
		$s1 = "chown root sh; chmod 4777 sh;" fullword ascii
		$s2 = "cp /bin/sh .;chown root sh;" fullword ascii
		$l1 = "echo clean up when elevated:" fullword ascii
		$x1 = "EXE=$DIR/sbin/ey_vrupdate" fullword ascii
	condition:
		( filesize < 4KB and 1 of them )
}