# Download and install FireFox
# Last updated:       2021/10/11
# Version: 0.01

$SourceURL = "https://download.mozilla.org/?product=firefox-msi-latest-ssl&os=win64&lang=en-US";

$Installer = $env:TEMP + "\firefox.msi"; 

Invoke-WebRequest $SourceURL -OutFile $Installer;

Start-Process msiexec.exe -Wait -ArgumentList "/i $Installer /qn" -Verb RunAs; 

Remove-Item $Installer;
