rule Trojan_Hacktool_Linux_Equation_noce3_451_398
{
    meta:
        judge = "black"
        threatname = "Trojan[Hacktool]/Linux.Equation.noce3"
        threattype = "Hacktool"
        family = "Equation"
        hacker = "None"
        author = "Florian Roth-copy"
        refer = "1d5bd438d76dd09edb91bbe81fc8e4f0"
        comment = "APT Equation Grou-https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
        date = "2018-07-24"
        description = "Equation Group hack tool set noclient_3_3_2"
	strings:
		$x1 = "127.0.0.1 is not advisable as a source. Use -l 127.0.0.1 to override this warning" fullword ascii
		$x2 = "iptables -%c OUTPUT -p tcp -d 127.0.0.1 --tcp-flags RST RST -j DROP;" fullword ascii
		$x3 = "noclient: failed to execute %s: %s" fullword ascii
		$x4 = "sh -c \"ping -c 2 %s; grep %s /proc/net/arp >/tmp/gx \"" fullword ascii
		$s5 = "Attempting connection from 0.0.0.0:" ascii
	condition:
		( filesize < 1000KB and 1 of them )
}