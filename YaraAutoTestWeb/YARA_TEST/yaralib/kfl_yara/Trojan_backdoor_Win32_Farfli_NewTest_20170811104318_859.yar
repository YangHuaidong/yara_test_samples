rule Trojan_backdoor_Win32_Farfli_NewTest_20170811104318_859 
{
	meta:
		judge = "black"
		threatname = "Trojan[backdoor]/Win32.Farfli.NewTest"
		threattype = "BackDoor"
		family = "Farfli"
		hacker = "none"
		refer = "19697676f886485b02b62ac3eeb29a26"
		description = "None"
		comment = "none"
		author = "xc"
		date = "2017-07-26"
	strings:
		$s0 = "tyrij"
		$s1 = "NewTest.dat"
		$s2 = "csm"

	condition:
		all of them
}
