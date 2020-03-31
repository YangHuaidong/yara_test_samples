rule Trojan_Backdoor_Linux_Derusbi_a_92_129
{
    meta:
        judge = "black"
        threatname = "Trojan[Backdoor]/Linux.Derusbi.a"
        threattype = "Backdoor"
        family = "Derusbi"
        hacker = "None"
        author = "dc"
        refer = "52A1B0DE364DFA9BAFABDE0C07BD90C2"
        comment = "None"
        date = "2018-04-29"
        description = "Derusbi Server Linux version __Airbus Defence and Space Cybersecurity CSIRT - Fabien Perigaud "
    strings:
        $PS1 = "PS1=RK# \\u@\\h:\\w \\$"
        $cmd = "unset LS_OPTIONS;uname -a"
        $pname = "[diskio]"
        $rkfile = "/tmp/.secure"
        $ELF = "\x7fELF"

    condition:
        $ELF at 0 and $PS1 and $cmd and $pname and $rkfile
}