/*
  Proton - Web kabukları (webshell).

  PHP, ASP/ASPX, JSP ve Node tabanlı sunucu tarafı arka kapıları. Kurallar
  kullanıcı girdisinin doğrudan yürütme çağrısına ulaştığı kalıpları arar.
*/

rule Proton_Php_Eval_Request_Webshell
{
  meta:
    description = "İstek parametresini doğrudan çalıştıran PHP web kabuğu"
    severity = "critical"
    category = "webshell"
    confidence = "high"
    author = "Neutron detection engineering"
  strings:
    $tag = "<?php" ascii nocase
    $input_1 = "$_POST[" ascii
    $input_2 = "$_GET[" ascii
    $input_3 = "$_REQUEST[" ascii
    $input_4 = "$_COOKIE[" ascii
    $input_5 = "php://input" ascii nocase
    $exec_1 = "eval(" ascii nocase
    $exec_2 = "assert(" ascii nocase
    $exec_3 = "system(" ascii nocase
    $exec_4 = "shell_exec(" ascii nocase
    $exec_5 = "passthru(" ascii nocase
    $exec_6 = "proc_open(" ascii nocase
    $exec_7 = "popen(" ascii nocase
    $exec_8 = "create_function(" ascii nocase
    $exec_9 = "call_user_func(" ascii nocase
    $obf_1 = "base64_decode(" ascii nocase
    $obf_2 = "gzinflate(" ascii nocase
    $obf_3 = "str_rot13(" ascii nocase
    $obf_4 = "preg_replace(\"/.*/e" ascii nocase
  condition:
    filesize < 2MB and $tag and 1 of ($input_*) and 1 of ($exec_*)
    and (1 of ($obf_*) or 2 of ($exec_*))
}

rule Proton_Php_Known_Webshell_Branding
{
  meta:
    description = "Bilinen PHP web kabuğu paneli imzaları"
    severity = "critical"
    category = "webshell"
    confidence = "high"
    author = "Neutron detection engineering"
  strings:
    $shell_1 = "c99shell" ascii nocase
    $shell_2 = "r57shell" ascii nocase
    $shell_3 = "WSO 2." ascii nocase
    $shell_4 = "b374k" ascii nocase
    $shell_5 = "IndoXploit" ascii nocase
    $shell_6 = "AnonymousFox" ascii nocase
    $shell_7 = "Alfa Team" ascii nocase
    $shell_8 = "priv8" ascii nocase
    $panel_1 = "safe_mode" ascii nocase
    $panel_2 = "Server IP" ascii nocase
    $panel_3 = "disable_functions" ascii nocase
    $panel_4 = "Symlink" ascii nocase
  condition:
    filesize < 3MB and (1 of ($shell_*) and 1 of ($panel_*) or 2 of ($shell_*))
}

rule Proton_Aspx_Runtime_Compile_Webshell
{
  meta:
    description = "Çalışma anında derleme yapan ASP.NET web kabuğu"
    severity = "critical"
    category = "webshell"
    confidence = "high"
    author = "Neutron detection engineering"
  strings:
    $page_1 = "<%@ Page" ascii nocase
    $page_2 = "<%@ Import" ascii nocase
    $input_1 = "Request.Item[" ascii nocase
    $input_2 = "Request.Form[" ascii nocase
    $input_3 = "Request.QueryString[" ascii nocase
    $input_4 = "Request[\"" ascii nocase
    $exec_1 = "System.Diagnostics.Process" ascii nocase
    $exec_2 = "ProcessStartInfo" ascii nocase
    $exec_3 = "CSharpCodeProvider" ascii nocase
    $exec_4 = "CompileAssemblyFromSource" ascii nocase
    $exec_5 = "Assembly.Load" ascii nocase
    $exec_6 = "cmd.exe" ascii nocase
    $exec_7 = "eval(" ascii nocase
  condition:
    filesize < 2MB and 1 of ($page_*) and 1 of ($input_*) and 2 of ($exec_*)
}

rule Proton_Jsp_Command_Execution_Webshell
{
  meta:
    description = "JSP tabanlı komut yürütme arka kapısı"
    severity = "critical"
    category = "webshell"
    confidence = "high"
    author = "Neutron detection engineering"
  strings:
    $jsp_1 = "<%@ page" ascii nocase
    $jsp_2 = "<%" ascii
    $input_1 = "request.getParameter(" ascii nocase
    $input_2 = "request.getHeader(" ascii nocase
    $input_3 = "request.getInputStream(" ascii nocase
    $exec_1 = "Runtime.getRuntime().exec" ascii nocase
    $exec_2 = "ProcessBuilder" ascii nocase
    $exec_3 = "defineClass" ascii nocase
    $exec_4 = "ClassLoader" ascii nocase
    $out_1 = "getOutputStream" ascii nocase
    $out_2 = "getInputStream" ascii nocase
  condition:
    filesize < 2MB and 1 of ($jsp_*) and 1 of ($input_*) and 1 of ($exec_*) and 1 of ($out_*)
}

rule Proton_China_Chopper_Style_Tiny_Shell
{
  meta:
    description = "Tek satırlık minimal web kabuğu kalıbı"
    severity = "critical"
    category = "webshell"
    confidence = "high"
    author = "Neutron detection engineering"
  strings:
    $chopper_1 = /<%[@ ]?[Ee]val[ \t]*\(?[ \t]*Request/ ascii nocase
    $chopper_2 = /<\?php[ \t]*@?eval\(\$_(POST|GET|REQUEST)\[/ ascii nocase
    $chopper_3 = "<%eval request(" ascii nocase
    $chopper_4 = /Page[ \t]+Language=["']Jscript["']/ ascii nocase
  condition:
    filesize < 64KB and 1 of them
}

rule Proton_Nodejs_Server_Backdoor
{
  meta:
    description = "Node.js sunucu tarafı komut yürütme arka kapısı"
    severity = "high"
    category = "webshell"
    confidence = "review"
    author = "Neutron detection engineering"
  strings:
    $req_1 = "require('child_process')" ascii nocase
    $req_2 = "require(\"child_process\")" ascii nocase
    $exec_1 = "exec(" ascii
    $exec_2 = "execSync(" ascii
    $exec_3 = "spawn(" ascii
    $input_1 = "req.query" ascii
    $input_2 = "req.body" ascii
    $input_3 = "req.headers" ascii
    $input_4 = "url.parse" ascii
    $eval_1 = "eval(" ascii
    $eval_2 = "new Function(" ascii
    $eval_3 = "Buffer.from(" ascii
  condition:
    filesize < 2MB and 1 of ($req_*) and 1 of ($exec_*) and 1 of ($input_*) and 1 of ($eval_*)
}

rule Proton_Webshell_File_Manager_Upload_Panel
{
  meta:
    description = "Sunucuda dosya yükleme ve yönetim paneli sunan arka kapı"
    severity = "high"
    category = "webshell"
    confidence = "review"
    author = "Neutron detection engineering"
  strings:
    $up_1 = "move_uploaded_file(" ascii nocase
    $up_2 = "$_FILES[" ascii
    $up_3 = "multipart/form-data" ascii nocase
    $mgr_1 = "opendir(" ascii nocase
    $mgr_2 = "scandir(" ascii nocase
    $mgr_3 = "unlink(" ascii nocase
    $mgr_4 = "chmod(" ascii nocase
    $mgr_5 = "file_put_contents(" ascii nocase
    $auth_1 = "md5($_POST" ascii nocase
    $auth_2 = "password" ascii nocase
    $exec_1 = "system(" ascii nocase
    $exec_2 = "shell_exec(" ascii nocase
    $exec_3 = "exec(" ascii nocase
  condition:
    filesize < 3MB and 2 of ($up_*) and 3 of ($mgr_*) and 1 of ($exec_*) and 1 of ($auth_*)
}
