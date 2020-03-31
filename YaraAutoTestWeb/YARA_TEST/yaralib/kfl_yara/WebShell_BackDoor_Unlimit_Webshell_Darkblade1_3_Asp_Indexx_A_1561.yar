rule WebShell_BackDoor_Unlimit_Webshell_Darkblade1_3_Asp_Indexx_A_1561 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2014/01/28"
    description = "Web Shell - file indexx.asp"
    family = "Webshell"
    hacker = "None"
    hash = "b7f46693648f534c2ca78e3f21685707"
    judge = "unknown"
    reference = "None"
    score = 70
    threatname = "WebShell[BackDoor]/Unlimit.Webshell.Darkblade1.3.Asp.Indexx.A"
    threattype = "BackDoor"
  strings:
    $s3 = "Const strs_toTransform=\"command|Radmin|NTAuThenabled|FilterIp|IISSample|PageCou"
  condition:
    all of them
}