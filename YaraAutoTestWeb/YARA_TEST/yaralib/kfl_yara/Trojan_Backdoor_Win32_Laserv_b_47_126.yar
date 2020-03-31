rule Trojan_Backdoor_Win32_Laserv_b_47_126
{
    meta:
        judge = "black"
				threatname = "Trojan[Backdoor]/Win32.Laserv.b"
				threattype = "Backdoor"
				family = "Laserv"
				hacker = "None"
				comment = "http://goo.gl/ivt8EW Equation_Kaspersky_EquationLaserInstaller"
				date = "2015-02-16"
				author = "Florian Roth--DC"
				description = "Equation Group Malware - EquationLaser Installer" 
				refer = "752af597e6d9fd70396accc0b9013dbe"

    strings:
        $mz = { 4d 5a }
        $s0 = "Failed to get Windows version" fullword ascii
        $s1 = "lsasrv32.dll and lsass.exe" fullword wide
        $s2 = "\\\\%s\\mailslot\\%s" fullword ascii
        $s3 = "%d-%d-%d %d:%d:%d Z" fullword ascii
        $s4 = "lsasrv32.dll" fullword ascii
        $s5 = "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!" fullword ascii
        $s6 = "%s %02x %s" fullword ascii
        $s7 = "VIEWERS" fullword ascii
        $s8 = "5.2.3790.220 (srv03_gdr.040918-1552)" fullword wide

    condition:
        ( $mz at 0 ) and filesize < 250000 and 6 of ($s*)
}