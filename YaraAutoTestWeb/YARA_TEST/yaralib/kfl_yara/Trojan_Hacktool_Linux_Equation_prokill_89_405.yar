rule Trojan_Hacktool_Linux_Equation_prokill_89_405
{
    meta:
        judge = "black"
        threatname = "Trojan[Hacktool]/Linux.Equation.prokill"
        threattype = "Hacktool"
        family = "Equation"
        hacker = "None"
        author = "Florian Roth-copy"
        refer = "3f9137377caecf68333b96ed737115f9"
        comment = "APT Equation Grou-https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
        date = "2018-07-09"
        description = "Equation Group hack tool leaked by ShadowBrokers- file promptkill"
	strings:
		$x1 = "exec(\"xterm $xargs -e /current/tmp/promptkill.kid.$tag $pid\");" fullword ascii
		$x2 = "$xargs=\"-title \\\"Kill process $pid?\\\" -name \\\"Kill process $pid?\\\" -bg white -fg red -geometry 202x19+0+0\" ;" fullword ascii
	condition:
		filesize < 250KB and 1 of them
}