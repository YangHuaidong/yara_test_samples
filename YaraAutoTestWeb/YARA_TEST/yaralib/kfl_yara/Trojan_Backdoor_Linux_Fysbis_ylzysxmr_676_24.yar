rule Trojan_Backdoor_Linux_Fysbis_ylzysxmr_676_24
{
    meta:
        judge = "black"
        threatname = "Trojan[Backdoor]/Linux.Fysbis.ylzysxmr"
        threattype = "backdoor"
        family = "Fysbis"
        hacker = "None"
        author = "balala"
        refer = "e107c5c84ded6cd9391aede7f04d64c8"
        comment = "None"
        date = "2018-08-30"
        description = "None"
	strings:
        $s1 = "RemoteShell" ascii
        $s2 = "basic_string::_M_replace_dispatch" fullword ascii
        $s3 = "HttpChannel" ascii
  
    condition:
        uint16(0) == 0x457f and filesize < 500KB and all of them

}