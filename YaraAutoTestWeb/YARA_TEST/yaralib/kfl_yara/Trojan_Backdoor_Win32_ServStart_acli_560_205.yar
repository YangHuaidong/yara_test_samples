rule Trojan_Backdoor_Win32_ServStart_acli_560_205
{
    meta:
        judge = "black"
        threatname = "Trojan[Backdoor]/Win32.ServStart.acli"
        threattype = "backdoor"
        family = "ServStart"
        hacker = "None"
        author = "bala"
        refer = "e9c5be4b58d6776282928c400d6a7d74"
        comment = "None"
        date = "2018-08-10"
        description = "None"
    strings:
        $s0 = "C:\\progra~1\\Common Files\\svc%c%c%c.exe" nocase wide ascii
        $s1 = "\\Install.bat" nocase wide ascii
        $s2 = "%04d%02d%02d" nocase wide ascii
        $s3 = "%c%c.exe" nocase wide ascii
		$s4 = "\\%c%c%c" nocase wide ascii
		$s9 = "HARDWARE\\DESCRIPTION\\System\\CentralProcessor\\0" nocase wide ascii
    condition:
        all of them
}