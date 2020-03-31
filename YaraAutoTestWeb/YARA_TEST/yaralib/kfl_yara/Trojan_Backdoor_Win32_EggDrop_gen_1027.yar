rule Trojan_Backdoor_Win32_EggDrop_gen_1027 
{
	meta:
		judge = "black"
		threatname = "Trojan[Backdoor]/Win32.EggDrop.gen"
		threattype = "Backdoor"
		family = "EggDrop"
		hacker = "None"
		refer = "91aed3b7d0a0fd8ba3da3b07e4294f0b"
		comment = "None"
		description = "Disclosed hacktool set (old stuff) - file asp1.txt"
		author = "Florian Roth"
		date = "23.11.14"
		
	strings:
		$s0 = "param = \"driver={Microsoft Access Driver (*.mdb)}\" " fullword ascii
		$s1 = "conn.Open param & \";dbq=\" & Server.MapPath(\"scjh.mdb\") " fullword ascii
		$s6 = "set rs=conn.execute (sql)%> " fullword ascii
		$s7 = "<%set Conn = Server.CreateObject(\"ADODB.Connection\") " fullword ascii
		$s10 = "<%dim ktdh,scph,scts,jhqtsj,yhxdsj,yxj,rwbh " fullword ascii
		$s15 = "sql=\"select * from scjh\" " fullword ascii
	condition:
		all of them
}