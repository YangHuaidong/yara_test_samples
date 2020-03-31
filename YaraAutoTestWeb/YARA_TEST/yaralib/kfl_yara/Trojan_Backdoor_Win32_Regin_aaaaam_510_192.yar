rule Trojan_Backdoor_Win32_Regin_aaaaam_510_192
{
    meta:
        judge = "black"
        threatname = "Trojan[Backdoor]/Win32.Regin.aaaaam"
        threattype = "Backdoor"
        family = "Regin"
        hacker = "None"
        author = "balala"
        refer = "6c34031d7a5fc2b091b623981a8ae61c"
		comment = "None"
        date = "2018-08-02"
        description = "https://securelist.com/blog/research/68438/an-analysis-of-regins-hopscotch-and-legspin/"
    

    strings:
        $mz="MZ"
        $a1="AuthenticateNetUseIpc"
        $a2="Failed to authenticate to"
        $a3="Failed to disconnect from"
        $a4="%S\\ipc$" wide
        $a5="Not deleting..."
        $a6="CopyServiceToRemoteMachine"
        $a7="DH Exchange failed"
        $a8="ConnectToNamedPipes"
  
    condition:
        ($mz at 0) and all of ($a*)
}