rule Trojan_RAT_Win32_MWgholee_V1_628_627
{
meta:

    judge = "black"
    threatname = "Trojan[RAT]/Win32.MWgholee.V1"
    threattype = "RAT"
    family = "MWgholee"
    hacker = "None"
    author = "@GelosSnake-lz"
    refer = "48573a150562c57742230583456b4c02"
    comment = "None"
    date = "2014/08"
    description = "http://securityaffairs.co/wordpress/28170/cyber-crime/gholee-malware.html"

    
  
strings:
    $a = "sandbox_avg10_vc9_SP1_2011"
    $b = "gholee"
   
condition:
    all of them
}