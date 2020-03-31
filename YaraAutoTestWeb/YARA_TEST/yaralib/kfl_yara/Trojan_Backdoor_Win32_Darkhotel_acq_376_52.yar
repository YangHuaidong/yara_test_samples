rule Trojan_Backdoor_Win32_Darkhotel_acq_376_52
{
    meta:
        judge = "black"
        threatname = "Trojan[Backdoor]/Win32.Darkhotel.acq"
        threattype = "Backdoor"
        family = "Darkhotel"
        hacker = "None"
        author = "Florian Roth-copy"
        refer = "5e01b8bc78afc6ecb3376c06cbceb680"
        comment = "None"
        date = "2018-06-20"
        description = "Detects sample mentioned in the Dubnium Report"
    strings:
        $key1 = "3b840e20e9555e9fb031c4ba1f1747ce25cc1d0ff664be676b9b4a90641ff194" fullword ascii
        $key2 = "90631f686a8c3dbc0703ffa353bc1fdf35774568ac62406f98a13ed8f47595fd" fullword ascii
    condition:
        uint16(0) == 0x5a4d and filesize < 2000KB and all of them
}