rule Trojan_Backdoor_Linux_Equation_toast_374_20
{
    meta:
        judge = "black"
        threatname = "Trojan[Backdoor]/Linux.Equation.toast"
        threattype = "Backdoor"
        family = "Equation"
        hacker = "None"
        author = "Florian Roth-copy"
        refer = "453e3685b9a0e3a17a831cb510185d30"
        comment = "APT Equation Grou-https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
        date = "2018-07-02"
        description = "Equation Group hack tool leaked by ShadowBrokers- toast_v3.2.0.1-linux"
	strings:
		$x2 = "Del --- Usage: %s -l file -w wtmp -r user" fullword ascii
		$s5 = "Roasting ->%s<- at ->%d:%d<-" fullword ascii
		$s6 = "rbnoil -Roasting ->" fullword ascii
	condition:
		( uint16(0) == 0x457f and filesize < 50KB and 1 of them )
}