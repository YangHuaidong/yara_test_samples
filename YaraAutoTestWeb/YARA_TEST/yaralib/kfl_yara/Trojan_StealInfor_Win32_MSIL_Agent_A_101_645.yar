rule Trojan_StealInfor_Win32_MSIL_Agent_A_101_645 
{
	meta:
		 judge = "black"
		 threatname = "Trojan[StealInfor]/Win32.MSIL_Agent.A"
		 threattype = "StealInfor"
		 family = "MSIL_Agent"
		 hacker = "apt15"
		 comment = "https://www.nccgroup.trust/us/about-us/newsroom-and-events/blog/2018/march/apt15-is-alive-and-strong-an-analysis-of-royalcli-and-royaldns/"
		 date = "2018-05-22"
		 author = "Ahmed Zaki--DC"
		 description = "malware_apt15_exchange_tool__This is a an exchange enumeration/hijacking tool used by an APT 15" 
		 refer = "d21a7e349e796064ce10f2f6ede31c71"
			
	strings:
		$s1= "subjectname" fullword
		$s2= "sendername" fullword
		$s3= "WebCredentials" fullword
		$s4= "ExchangeVersion"	fullword
		$s5= "ExchangeCredentials"	fullword
		$s6= "slfilename"	fullword
		$s7= "EnumMail"	fullword
		$s8= "EnumFolder"	fullword
		$s9= "set_Credentials"	fullword
		$s10 = "/de" wide
		$s11 = "/sn" wide
		$s12 = "/sbn" wide
		$s13 = "/list" wide
		$s14 = "/enum" wide
		$s15 = "/save" wide
		$s16 = "/ao" wide
		$s17 = "/sl" wide
		$s18 = "/v or /t is null" wide
		$s19 = "2007" wide
		$s20 = "2010" wide
		$s21 = "2010sp1" wide
		$s22 = "2010sp2" wide
		$s23 = "2013" wide
		$s24 = "2013sp1" wide
	condition:
		uint16(0) == 0x5A4D and 15 of ($s*)
}
