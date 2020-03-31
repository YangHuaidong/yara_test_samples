rule Trojan_Linux_WeakPwd_killed_20170407172751_1064_565 
{
	meta:
		judge = "black"
		threatname = "Trojan/Linux.WeakPwd.killed"
		threattype = "DDOS"
		family = "WeakPwd"
		hacker = "None"
		refer = "c116823be2b700d66f912fd216c9f606"
		description = "Unkown Virus Family,Weak password blasting"
		comment = "None"
		author = "DJW"
		date = "2017-03-30"
	strings:
		$s0 = "flood"
		$s1 = "killall -9 dex.%s"
		$s2 = "Terminato"
		$s3 = "dreambox"
		$s4 = "ZOMBIE"
		$s5 = "fin.ack.psh"
		$s6 = "/bin/busybox d4rk3v1l"
		$s7 = "4|User:"

	condition:
		5 of them
}
