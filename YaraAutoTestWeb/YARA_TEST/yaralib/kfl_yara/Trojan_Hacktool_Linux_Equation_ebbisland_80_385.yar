rule Trojan_Hacktool_Linux_Equation_ebbisland_80_385
{
    meta:
        judge = "black"
        threatname = "Trojan[Hacktool]/Linux.Equation.ebbisland"
        threattype = "Hacktool"
        family = "Equation"
        hacker = "None"
        author = "Florian Roth-copy"
        refer = "4b9fa1d17fda9e879d68b069df3a7e2a"
        comment = "APT Equation Grou-https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
        date = "2018-07-09"
        description = "Equation Group hack tool leaked by ShadowBrokers- file ebbisland"
	strings:
		$x1 = "Usage: %s [-V] -t <target_ip> -p port" fullword ascii
		$x2 = "error - shellcode not as expected - unable to fix up" fullword ascii
		$x3 = "WARNING - core wipe mode - this will leave a core file on target" fullword ascii
		$x4 = "[-C] wipe target core file (leaves less incriminating core on failed target)" fullword ascii
		$x5 = "-A <jumpAddr> (shellcode address)" fullword ascii
		$x6 = "*** Insane undocumented incremental port mode!!! ***" fullword ascii
	condition:
		filesize < 250KB and 1 of them
}