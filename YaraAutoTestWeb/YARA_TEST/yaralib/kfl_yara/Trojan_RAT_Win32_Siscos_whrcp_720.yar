rule Trojan_RAT_Win32_Siscos_whrcp_720
{
    meta:
        judge = "black"
        threatname = "Trojan[RAT]/Win32.Siscos.whrcp"
        threattype = "RAT"
        family = "Siscos"
        hacker = "None"
        author = "copy"
        refer = "006e0674bd7847c2467589179c36f59f"
        comment = "None"
        date = "2017-09-13"
        description = "None"
    strings:
        $s0 = "cgi_ger_noprpair" nocase wide ascii
        $s1 = "SSBKSPT" nocase wide ascii
        $s2 = "npogpam" nocase wide ascii
    condition:
        all of them
}