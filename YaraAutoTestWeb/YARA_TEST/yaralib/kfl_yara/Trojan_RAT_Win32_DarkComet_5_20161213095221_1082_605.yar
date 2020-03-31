rule Trojan_RAT_Win32_DarkComet_5_20161213095221_1082_605 
{
	meta:
		judge = "black"
		threatname = "Trojan[Backdoor]/Win32.DarkComet.5"
		threattype = "rat"
		family = "DarkComet"
		hacker = "None"
		refer = "37b3f4d89a12086a950130fc6a800f41"
		description = "VertexNet"
		comment = "None"
		author = "Brian Wallace @botnet_hunter"
		date = "2016-06-23"
	strings:
		$s0 = "vertexnet" nocase
		$s1 = "urldl::"
		$s2 = "%LAPPDATA%"
		$s3 = "[ERROR] while loading ressource"

	condition:
		all of them
}
