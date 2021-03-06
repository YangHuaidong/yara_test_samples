rule Trojan_DDoS_Win32_Mirai_Cracker_20170407172746_1014_305 
{
	meta:
		judge = "black"
		threatname = "Trojan[DDoS]/Win32.Mirai.Cracker"
		threattype = "DDOS"
		family = "Mirai"
		hacker = "None"
		refer = "e4093478cf66f9c5b4224792a941510f,9fd999d823c658fc8b29f8dfab43a1a2,1c257c14a745053664f046174b0ef543"
		description = "None"
		comment = "None"
		author = "djw"
		date = "2017-03-29"
	strings:
		$s0 = "CheckUpdate.cpp"
		$s1 = "Cracker_Inline.cpp"
		$s2 = "Cracker_Standalone.cpp"
		$s3 = "cService.cpp"
		$s4 = "CThreadPool.cpp"
		$s5 = "Db_Mysql.cpp"
		$s6 = "Dispatcher.cpp"
		$s7 = "IpFetcher.cpp"
		$s8 = "libtelnet.cpp"
		$s9 = "Logger_Stdout.cpp"
		$s10 = "Scanner_Tcp_Connect.cpp"
		$s11 = "Scanner_Tcp_Raw.cpp"
		$s12 = "ServerAgent.cpp"
		$s13 = "Task_Crack_Ipc.cpp"
		$s14 = "Task_Crack_Mssql.cpp"
		$s15 = "Task_Crack_Rdp.cpp"
		$s16 = "Task_Crack_Ssh.cpp"
		$s17 = "Task_Crack_Telnet.cpp"
		$s18 = "Task_Crack_Wmi.cpp"
		$s19 = "Task_Scan.cpp"
		$s20 = "WPD.cpp"
		$s21 = "catdbsvc.cpp"
		$s22 = "catadnew.cpp"
		$s23 = "catdbcli.cpp"
		$s24 = "waitsvc.cpp"
		$s25 = "errlog.cpp"
		$s26 = "Cracker:MSSQL"
		$s27 = "Cracker:Telnet"
		$a0 = "/bin/busybox ECCHI"
		$a1 = "dvrHelper"
		$a2 = "down2.b5w91.com:8443"

	condition:
		(3 of ($s*) and 1 of ($a*))
}
