rule Trojan_DownLoader_Win32_Farfli_docp_698
{
    meta:
        judge = "black"
        threatname = "Trojan[DownLoader]/Win32.Farfli.docp"
        threattype = "DownLoader"
        family = "Farfli"
        hacker = "None"
        author = "copy"
        refer = "e23dee5b76393b6514d1ff68441c831b"
        comment = "None"
        date = "2017-09-14"
        description = "None"
    strings:
        $s0 = "MbWdP7WG" nocase wide ascii
        $s1 = "tem\\CentralProcessor\\0" nocase wide ascii
        $s2 = "mozi" nocase wide ascii
        $s3 = "HARDWARE\\DES" nocase wide ascii
    condition:
        all of them
}