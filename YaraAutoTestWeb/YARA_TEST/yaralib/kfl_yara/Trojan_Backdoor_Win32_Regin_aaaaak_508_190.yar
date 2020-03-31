rule Trojan_Backdoor_Win32_Regin_aaaaak_508_190
{
    meta:
        judge = "black"
        threatname = "Trojan[Backdoor]/Win32.Regin.aaaaak"
        threattype = "Backdoor"
        family = "Regin"
        hacker = "None"
        author = "balala"
        refer = "55b8dbe7bb0c37c05a30cc75742401a5,b7cbb79edd04c32dc46e23407d0c4139"
		comment = "None"
        date = "2018-08-02"
        description = "Detects Regin Backdoor sample 4139149552b0322f2c5c993abccc0f0d1b38db4476189a9f9901ac0d57a656be and e420d0cf7a7983f78f5a15e6cb460e93c7603683ae6c41b27bf7f2fa34b2d935"
    

    strings:
        $hd = { fe ba dc fe }    
        $s0 = "d%ls%ls" fullword wide
        $s1 = "\\\\?\\UNC" fullword wide
        $s2 = "Software\\Microsoft\\Windows\\CurrentVersion" fullword wide
        $s3 = "\\\\?\\UNC\\" fullword wide
        $s4 = "SYSTEM\\CurrentControlSet\\Control\\Class\\{4D36E972-E325-11CE-BFC1-08002BE10318}" fullword wide
        $s5 = "System\\CurrentControlSet\\Services\\Tcpip\\Linkage" wide fullword
        $s6 = "\\\\.\\Global\\%s" fullword wide
        $s7 = "temp" fullword wide
        $s8 = "\\\\.\\%s" fullword wide
        $s9 = "Memory location: 0x%p, size 0x%08x" fullword wide        
        
        $s10 = "sscanf" fullword ascii
        $s11 = "disp.dll" fullword ascii
        $s12 = "%x:%x:%x:%x:%x:%x:%x:%x%c" fullword ascii
        $s13 = "%d.%d.%d.%d%c" fullword ascii
        $s14 = "imagehlp.dll" fullword ascii
        $s15 = "%hd %d" fullword ascii
   
    condition:
        ( $hd at 0 ) and all of ($s*) and filesize < 450KB and filesize > 360KB
}