rule WebShell_BackDoor_Unlimit_Webshell_Browser_201_3_Ma_Download_A_1529 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2014/01/28"
    description = "Web Shell - from files browser.jsp, 201.jsp, 3.jsp, ma.jsp, download.jsp"
    family = "Webshell"
    hacker = "None"
    hash0 = "37603e44ee6dc1c359feb68a0d566f76"
    hash1 = "a7e25b8ac605753ed0c438db93f6c498"
    hash2 = "fb8c6c3a69b93e5e7193036fd31a958d"
    hash3 = "4cc68fa572e88b669bce606c7ace0ae9"
    hash4 = "fa87bbd7201021c1aefee6fcc5b8e25a"
    judge = "unknown"
    reference = "None"
    score = 70
    super_rule = 1
    threatname = "WebShell[BackDoor]/Unlimit.Webshell.Browser.201.3.Ma.Download.A"
    threattype = "BackDoor"
  strings:
    $s2 = "<small>jsp File Browser version <%= VERSION_NR%> by <a"
    $s3 = "else if (fName.endsWith(\".mpg\") || fName.endsWith(\".mpeg\") || fName.endsWith"
  condition:
    all of them
}