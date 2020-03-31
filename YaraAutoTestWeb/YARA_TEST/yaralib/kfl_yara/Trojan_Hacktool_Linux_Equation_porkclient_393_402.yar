rule Trojan_Hacktool_Linux_Equation_porkclient_393_402
{
    meta:
        judge = "black"
        threatname = "Trojan[Hacktool]/Linux.Equation.porkclient"
        threattype = "Hacktool"
        family = "Equation"
        hacker = "None"
        author = "Florian Roth-copy"
        refer = "509189ed957d0d5d354078ea1850350d"
        comment = "APT Equation Grou-https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
        date = "2018-07-02"
        description = "Equation Group hack tool leaked by ShadowBrokers- file porkclient"
	strings:
		$s1 = "-c COMMAND: shell command string" fullword ascii
		$s2 = "Cannot combine shell command mode with args to do socket reuse" fullword ascii
		$s3 = "-r: Reuse socket for Nopen connection (requires -t, -d, -f, -n, NO -c)" fullword ascii
	condition:
		( uint16(0) == 0x457f and filesize < 30KB and 1 of them )
}