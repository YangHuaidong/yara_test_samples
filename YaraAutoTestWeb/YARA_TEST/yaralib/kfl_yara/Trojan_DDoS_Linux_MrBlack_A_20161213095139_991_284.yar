rule Trojan_DDoS_Linux_MrBlack_A_20161213095139_991_284 
{
	meta:
		judge = "black"
		threatname = "Trojan[Backdoor]/Linux.Mayday.a"
		threattype = "rat"
		family = "Mayday"
		hacker = "None"
		refer = "http://www.kernelmode.info/forum/viewtopic.php?f=16&t=3483,5cd17ae8b2cc941c7ec19d3ef1415bbf"
		description = "Strings inside"
		comment = "None"
		author = "@benkow_"
		date = "2014-09-12"
	strings:
		$a = "Mr.Black"
		$b = "VERS0NEX:%s|%d|%d|%s"

	condition:
		$a and $b
}
