rule Trojan_Backdoor_Win32_DoubleFantasy_gen_23_57
{
    meta:
        judge = "black"
				threatname = "Trojan[Backdoor]/Win32.DoubleFantasy.gen"
				threattype = "Backdoor"
				family = "DoubleFantasy"
				hacker = "None"
				comment = "http://goo.gl/ivt8EW Equation_Kaspersky_DoubleFantasy_1"
				date = "2015-02-16"
				author = "Florian Roth--DC"
				description = "Equation Group Malware - DoubleFantasy http://goo.gl/ivt8EW" 
				refer = "2a12630ff976ba0994143ca93fecd17f"
    strings:
        $mz = { 4d 5a }
        $z1 = "msvcp5%d.dll" fullword ascii
        $s0 = "actxprxy.GetProxyDllInfo" fullword ascii
        $s3 = "actxprxy.DllGetClassObject" fullword ascii
        $s5 = "actxprxy.DllRegisterServer" fullword ascii
        $s6 = "actxprxy.DllUnregisterServer" fullword ascii
        $x1 = "yyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyy" ascii
        $x2 = "191H1a1" fullword ascii
        $x3 = "November" fullword ascii
        $x4 = "abababababab" fullword ascii
        $x5 = "January" fullword ascii
        $x6 = "October" fullword ascii
        $x7 = "September" fullword ascii
    condition:
        ( $mz at 0 ) and filesize < 350000 and (( $z1 ) or ( all of ($s*) and 6 of ($x*) ))
}