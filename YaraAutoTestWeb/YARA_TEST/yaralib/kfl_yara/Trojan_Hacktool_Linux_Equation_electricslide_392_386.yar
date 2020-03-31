rule Trojan_Hacktool_Linux_Equation_electricslide_392_386
{
    meta:
        judge = "black"
        threatname = "Trojan[Hacktool]/Linux.Equation.electricslide"
        threattype = "Hacktool"
        family = "Equation"
        hacker = "None"
        author = "Florian Roth-copy"
        refer = "460ea0becd542c42482b111a33e8aaab"
        comment = "APT Equation Grou-https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
        date = "2018-07-02"
        description = "Equation Group hack tool leaked by ShadowBrokers- file electricslide"
	strings:
		$x1 = "Firing with the same hosts, on altername ports (target is on 8080, listener on 443)" fullword ascii
		$x2 = "Recieved Unknown Command Payload: 0x%x" fullword ascii
		$x3 = "Usage: eslide   [options] <-t profile> <-l listenerip> <targetip>" fullword ascii
		$x4 = "-------- Delete Key - Remove a *closed* tab" fullword ascii
	condition:
		( uint16(0) == 0x457f and filesize < 2000KB and 1 of them )
}