rule Trojan_Backdoor_Win32_Winnti_h_77_238
{
    meta:
        judge = "black"
        threatname = "Trojan[Backdoor]/Win32.Winnti.h"
        threattype = "Backdoor"
        family = "Winnti"
        hacker = "None"
        author = "dc"
        refer = "24E9870973CEA42E6FAF705B14208E52,6668E339D1F11A724AA286593C192472,422F3353164AAE7AFA7429E6721703CC,3F3D35208BFE32E64F82593EE89FF462"
        comment = "None"
        date = "2015-12-09"
        description = "Derusbi Driver version__Airbus Defence and Space Cybersecurity CSIRT - Fabien Perigaud rootkit"
    strings:
        $token1 = "$$$--Hello"     
        $token2 = "Wrod--$$$"   
        $cfg = "XXXXXXXXXXXXXXX"
        $class = ".?AVPCC_BASEMOD@@"
        $MZ = "MZ"

    condition:
        $MZ at 0 and $token1 and $token2 and $cfg and $class
}