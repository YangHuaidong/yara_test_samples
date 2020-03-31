rule WebShell_BackDoor_Unlimit_Webshell_404_Data_Suiyue_A_1485 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2014/01/28"
    description = "Web Shell - from files 404.jsp, data.jsp, suiyue.jsp"
    family = "Webshell"
    hacker = "None"
    hash0 = "7066f4469c3ec20f4890535b5f299122"
    hash1 = "9f54aa7b43797be9bab7d094f238b4ff"
    hash2 = "c93d5bdf5cf62fe22e299d0f2b865ea7"
    judge = "unknown"
    reference = "None"
    score = 70
    super_rule = 1
    threatname = "WebShell[BackDoor]/Unlimit.Webshell.404.Data.Suiyue.A"
    threattype = "BackDoor"
  strings:
    $s3 = " sbCopy.append(\"<input type=button name=goback value=' \"+strBack[languageNo]+"
  condition:
    all of them
}