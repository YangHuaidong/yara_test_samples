rule Trojan_Backdoor_Win32_Farfli_360SoftwareManager_20170720120035_907_83 
{
	meta:
		judge = "black"
		threatname = "Trojan[Backdoor]/Win32.Farfli.360SoftwareManager"
		threattype = "BackDoor"
		family = "Farfli"
		hacker = "none"
		refer = "abbe8ad34e3ab32ad1baee45ac464da3"
		description = "None"
		comment = "none"
		author = "xc"
		date = "2017-07-14"
	strings:
		$s0 = "Install.dat"
		$s1 = "winspool.drv"
		$s2 = "PjZBM0AA"
		$s3 = "Pzcjwj8zB9VP"
		$s4 = "7ed0908296cb48c6a312d52753bfeed0"

	condition:
		all of them
}
