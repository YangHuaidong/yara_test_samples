rule Trojan_Hacktool_Linux_Equation_gr_448_391
{
    meta:
        judge = "black"
        threatname = "Trojan[Hacktool]/Linux.Equation.gr"
        threattype = "Hacktool"
        family = "Equation"
        hacker = "None"
        author = "Florian Roth-copy"
        refer = "4217ad2b11c42ff540695f693ce6e4b1"
        comment = "APT Equation Grou-https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
        date = "2018-07-24"
        description = "Equation Group hack tool set gr"
	strings:
		$s1 = "if [ -f /tmp/tmpwatch ] ; then" fullword ascii
		$s2 = "echo \"bailing. try a different name\"" fullword ascii
	condition:
		( filesize < 1KB and all of them )
}