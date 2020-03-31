rule Trojan_DDoS_Linux_MrBlack_35_1050
{
	meta:
		judge = "black"
		threatname = "Trojan[DDoS]/Linux.MrBlack.A"
		threattype = "DDoS"
		family = "MrBlack"
		hacker = "None"
		refer = "8894173e6334e31624dc458583232656"
		author = "lizhenling"
		comment = "None"
		date = "2019-02-26"
		description = "None"

	strings:		
		$s0 = "StopFlag2"
		$s1 = "socket create failse...GetLocalIp!/n"
		$s2 = "_Z8CmdShellPv"
		$s3 = "_Z6strrevPc"
		$s4 = "pthread_join@@GLIBC_2.0"
		$s5 = "_Z15TurnonKeepAliveij"
		$s6 = "linux_data"
		$s7 = "Admin_MainSocket"
		
	condition:
		7 of them
}