rule Trojan_Dropper_Win32_Zusy_hrdldsb_808_376
{
    meta:
        judge = "black"
        threatname = "Trojan[Dropper]/Win32.Zusy.hrdldsb"
        threattype = "Dropper"
        family = "Zusy"
        hacker = "None"
        author = "balala"
        refer = "63558e2980d1c6aaf34beefb657866fe,f89a4d4ae5cca6d69a5256c96111e707"
        comment = "None"
        date = "2018-10-22"
        description = "None"
	strings:
        $x1 = "... get header FATAL ERROR !!!  %d bytes read > header_size" fullword ascii
        $x2 = "index.php?c=%S&r=%x&u=1&t=%S" fullword wide
        $x3 = "connect_back_tcp_channel#do_connect:: Error resolving connect back hostname" fullword ascii
        $s0 = "kernel32.dll GetProcAddressLoadLibraryAws2_32.dll" fullword ascii
        $s1 = "Content-Type: multipart/form-data; boundary=%S" fullword wide
        $s2 = "Attempting to unlock uninitialized lock!" fullword ascii
        $s4 = "unable to load kernel32.dll" fullword ascii
        $s5 = "index.php?c=%S&r=%x" fullword wide
        $s6 = "%s len:%d " fullword ascii
        $s7 = "Encountered error sending syscall response to client" fullword ascii
        $s9 = "/info.dat" fullword ascii
        $s10 = "Error entering thread lock" fullword ascii
        $s11 = "Error exiting thread lock" fullword ascii
        $s12 = "connect_back_tcp_channel_init:: socket() failed" fullword ascii
   
    condition:
        ( 1 of ($x*) ) or ( 8 of ($s*) )
}