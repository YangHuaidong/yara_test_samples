rule Trojan_Backdoor_Linux_Equation_packrat_371_17
{
    meta:
        judge = "black"
        threatname = "Trojan[Backdoor]/Linux.Equation.packrat"
        threattype = "Backdoor"
        family = "Equation"
        hacker = "None"
        author = "Florian Roth-copy"
        refer = "75c94c84db1c18a3d405f8d4f04c8f80"
        comment = "APT Equation Grou-https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
        date = "2018-07-02"
        description = "Equation Group hack tool leaked by ShadowBrokers- packrat"
	strings:
		$x2 = "Use this on target to get your RAT:" fullword ascii
		$x3 = "$ratremotename && " fullword ascii
		$x5 = "$command = \"$nc$bindto -vv -l -p $port < ${ratremotename}\" ;" fullword ascii
	condition:
		( filesize < 70KB and 1 of them )
}