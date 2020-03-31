rule Trojan_RAT_Win32_Magania_NET_20170811104339_977 
{
	meta:
		judge = "black"
		threatname = "Trojan[RAT]/Win32.Magania.NET"
		threattype = "rat"
		family = "Magania"
		hacker = "none"
		refer = "01f26dab28aa34deecfd62495a9c3366"
		description = "None"
		comment = "none"
		author = "xc"
		date = "2017-07-25"
	strings:
		$s0 = "Netroot.dat"
		$s1 = "221.231.6.91"

	condition:
		all of them
}
