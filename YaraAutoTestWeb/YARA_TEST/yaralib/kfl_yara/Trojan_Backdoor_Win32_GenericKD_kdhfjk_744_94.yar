rule Trojan_Backdoor_Win32_GenericKD_kdhfjk_744_94
{
    meta:
        judge = "black"
        threatname = "Trojan[Backdoor]/Win32.GenericKD.kdhfjk"
        threattype = "Backdoor"
        family = "GenericKD"
        hacker = "None"
        author = "balala"
        refer = "60bcc6bc746078d81a9cd15cd4f199bb"
        comment = "None"
        date = "2018-09-27"
        description = "None"
	strings:
        $ = "dcom_api" ascii
        $ = "http://*:80/OWA/OAB/" ascii
        $ = "https://*:443/OWA/OAB/" ascii
        $ = "dcomnetsrv.cpp" wide
        $ = "dcomnet.dll" ascii
        $ = "D:\\Develop\\sps\\neuron2\\x64\\Release\\dcomnet.pdb" ascii
    condition:
        (uint16(0) == 0x5A4D and uint16(uint32(0x3c)) == 0x4550) and 2 of them
}