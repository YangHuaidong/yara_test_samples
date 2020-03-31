rule WebShell_BackDoor_Unlimit_Ajax_Fileupload_Webshell_A_1173 {
  meta:
    author = "Spider"
    comment = "None"
    date = "12.10.2014"
    description = "AJAX JS/CSS components providing web shell by APT groups"
    family = "Ajax"
    hacker = "None"
    judge = "unknown"
    reference = "http://ceso.googlecode.com/svn/web/bko/filemanager/ajaxfileupload.js"
    score = 75
    threatname = "WebShell[BackDoor]/Unlimit.Ajax.Fileupload.Webshell.A"
    threattype = "BackDoor"
  strings:
    $a1 = "var frameId = 'jUploadFrame' + id;" ascii
    $a2 = "var form = jQuery('<form  action=\"\" method=\"POST\" name=\"' + formId + '\" id=\"' + formId + '\" enctype=\"multipart/form-data\"></form>');" ascii
    $a3 = "jQuery(\"<div>\").html(data).evalScripts();" ascii
  condition:
    all of them
}