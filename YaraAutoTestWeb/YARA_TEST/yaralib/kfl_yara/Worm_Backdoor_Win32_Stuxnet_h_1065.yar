rule Worm_Backdoor_Win32_Stuxnet_h_1065
{
	meta:
		judge = "black"
		threatname = "Worm[Backdoor]/Win32.Stuxnet.h"
		threattype = "ICS,Backdoor"
		family = "Stuxnet"
		hacker = "None"
		refer = "68eb6d3adc49da0a79aff2202bbb3bea"
		author = "LiuGuangzhu"
		comment = "None"
		date = "2019-03-09"
		description = "None"
    strings:
        $s1 = "%SystemRoot%\\system32\\Drivers\\mrxsmb.sys;%SystemRoot%\\system32\\Drivers\\*.sys" fullword wide
        $s2 = "<Actions Context=\"%s\"><Exec><Command>%s</Command><Arguments>%s,#%u</Arguments></Exec></Actions>" fullword wide
        $s3 = "%SystemRoot%\\inf\\oem7A.PNF" fullword wide
        $s4 = "%SystemRoot%\\inf\\mdmcpq3.PNF" fullword wide
        $s5 = "%SystemRoot%\\inf\\oem6C.PNF" fullword wide
        $s6 = "@abf varbinary(4096) EXEC @hr = sp_OACreate 'ADODB.Stream', @aods OUT IF @hr <> 0 GOTO endq EXEC @hr = sp_OASetProperty @" wide
        $s7 = "STORAGE#Volume#1&19f7e59c&0&" fullword wide
        $s8 = "view MCPVREADVARPERCON as select VARIABLEID,VARIABLETYPEID,FORMATFITTING,SCALEID,VARIABLENAME,ADDRESSPARAMETER,PROTOKOLL,MAXLIMI" ascii
    condition:
         6 of them
}