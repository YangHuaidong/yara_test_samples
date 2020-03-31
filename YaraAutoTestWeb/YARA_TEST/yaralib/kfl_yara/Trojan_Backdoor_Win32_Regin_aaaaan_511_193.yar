rule Trojan_Backdoor_Win32_Regin_aaaaan_511_193
{
    meta:
        judge = "black"
        threatname = "Trojan[Backdoor]/Win32.Regin.aaaaan"
        threattype = "Backdoor"
        family = "Regin"
        hacker = "None"
        author = "balala"
        refer = "bddf5afbea2d0eed77f2ad4e9a4f044d,c053a0a3f1edcbbfc9b51bc640e808ce"
		comment = "None"
        date = "2018-08-02"
        description = "Rule to detect Regin 64 bit stage 1 loaders"
    

    strings:
        $mz="MZ"
        $a1="PRIVHEAD"
        $a2="\\\\.\\PhysicalDrive%d"
        $a3="ZwDeviceIoControlFile"

    condition:
        ($mz at 0) and (all of ($a*)) and filesize < 100000
}