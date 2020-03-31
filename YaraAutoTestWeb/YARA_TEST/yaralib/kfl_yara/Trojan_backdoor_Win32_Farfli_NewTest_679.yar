rule Trojan_backdoor_Win32_Farfli_NewTest_679
{
    meta:
	        judge = "black"
			threatname = "Trojan[backdoor]/Win32.Farfli.NewTest"
			threattype = "backdoor"
			family = "Farfli"
			hacker = "none"
			refer = "19697676f886485b02b62ac3eeb29a26"
			comment = "none"
			author = "xc"
			date = "2017-07-26"
			description = "None"
	strings:
			$s0 = "tyrij"
			$s1 = "NewTest.dat"
			$s2 = "csm"
    condition:
            all of them
}