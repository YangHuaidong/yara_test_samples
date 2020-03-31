rule Trojan_Backdoor_Linux_Equation_calserver_368_9
{
    meta:
        judge = "black"
        threatname = "Trojan[Backdoor]/Linux.Equation.calserver"
        threattype = "Backdoor"
        family = "Equation"
        hacker = "None"
        author = "Florian Roth-copy"
        refer = "4e03a3dfbe5e259957e97b9690f21d0a"
        comment = "APT Equation Grou-https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
        date = "2018-07-02"
        description = "Equation Group hack tool leaked by ShadowBrokers- calserver"
	strings:
		$x1 = "usage: %s <host> <port> e <contents of a local file to be executed on target>" fullword ascii
		$x2 = "Writing your %s to target." fullword ascii
		$x3 = "(e)xploit, (r)ead, (m)ove and then write, (w)rite" fullword ascii
	condition:
		( uint16(0) == 0x457f and filesize < 30KB and 1 of them )
}