rule Trojan_Backdoor_Win32_Regin_aaaaal_509_191
{
    meta:
        judge = "black"
        threatname = "Trojan[Backdoor]/Win32.Regin.aaaaal"
        threattype = "Backdoor"
        family = "Regin"
        hacker = "None"
        author = "balala"
        refer = "29105f46e4d33f66fee346cfd099d1cc"
		comment = "None"
        date = "2018-08-02"
        description = "https://securelist.com/blog/research/68438/an-analysis-of-regins-hopscotch-and-legspin/"
    

    strings:
        $mz="MZ"
        $a1="sharepw"
        $a2="reglist"
        $a3="logdump"
        $a4="Name:" wide
        $a5="Phys Avail:"
        $a6="cmd.exe" wide
        $a7="ping.exe" wide
        $a8="millisecs"
   
    condition:
        ($mz at 0) and all of ($a*)
}