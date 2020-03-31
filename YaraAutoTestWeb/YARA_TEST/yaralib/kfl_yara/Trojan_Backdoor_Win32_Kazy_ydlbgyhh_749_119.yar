rule Trojan_Backdoor_Win32_Kazy_ydlbgyhh_749_119
{
    meta:
        judge = "black"
        threatname = "Trojan[Backdoor]/Win32.Kazy.ydlbgyhh"
        threattype = "Backdoor"
        family = "Kazy"
        hacker = "None"
        author = "ljy"
        refer = "af785b4df71da0786bcae233e55cf6c1,c7c2be1cd3780b2ba4638cef9a5422c7,ea4dcafc224f604c096032dde33a1d6d,ae66bad0c7de88ab0ab1050c4bec9095,e404873d3fcd0268db10657b53bdab64,d8f0a6450f9df637daade521dc90d29d,40092f76fea082b05e9631d91975a401,8ea5d8bb6b28191e4436456c35477e39,996843b55a7c5c7a36e8c6956e599610,5cd0e97a1f09001af5213462aa3f7eb1,2b95caf3307ebd36cf405b1133b30aa8,2813c5a1c87f7e3d33174fed8b0988a1,692cecc94ac440ec673dc69f37bc0409,46cf2f9b4a4c35b62a32f28ac847c575,225e10e362eeee15ec64246ac021f4d6,396b4317db07cc8a2480786160b33044,5436c3469cb1d87ea404e8989b28758d,03e1eac3512a726da30fff41dbc26039,42d874f91145bd2ddf818735346022d8,ddbdf0efdf26e0c267ef6155edb0e6b8"
        comment = "None"
        date = "2018-09-20"
        description = "None"
	strings:
        $s0 = "%d|%s|%04d/%02d/%02d %02d:%02d:%02d|%ld|%d" fullword wide 
        $s1 = "HttpBrowser/1.0" fullword wide
        $s2 = "set cmd : %s" ascii fullword
        $s3 = "\\config.ini" wide fullword
  
    condition:
        uint16(0) == 0x5a4d and filesize < 45KB and filesize > 20KB and all of them
}