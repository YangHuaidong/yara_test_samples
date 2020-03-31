rule Worm_Backdoor_Win32_Stuxnet_Shortcut_1066
{
	meta:
		judge = "black"
		threatname = "Worm[Backdoor]/Win32.Stuxnet.Shortcut"
		threattype = "ICS,Backdoor"
		family = "Stuxnet"
		hacker = "None"
		refer = "984c857ca2979af776647061c8ae3acc"
		author = "LiuGuangzhu"
		comment = "None"
		date = "2019-03-09"
		description = "None"
    strings:
        $x1 = "\\\\.\\STORAGE#Volume#_??_USBSTOR#Disk&Ven_Kingston&Prod_DataTraveler_2.0&Rev_PMAP#5B6B098B97BE&0#{53f56307-b6bf-11d0-94f2-00a0c" wide
    condition:
        uint16(0) == 0x004c and filesize < 10KB and $x1
}