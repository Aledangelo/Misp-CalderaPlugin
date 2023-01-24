# EXAMPLES

## How to import

On the MISP platform it is possible to import files in MISP or STIX format. In order to do this, you have to log in with your account and click the button **Import from...**

![alt text](https://raw.githubusercontent.com/Aledangelo/Misp-CalderaPlugin/main/img/import.png)

## Malware Descriptions
### Poison Ivy
Poison Ivy variants are backdoors that are created and controlled by a Poison Ivy management program or kit.
The Poison Ivy kit has a graphical user interface and is actively developed. The servers (the actual backdoors) are very small and are typically under 10kB in size. The size can however be considerably different if a packer or protector has been used to obfuscate the file.

<div style="text-align:center;"><img src="https://www.f-secure.com/virus-info/v-pics/poisonIvy-client.JPG" /></div>

Backdoor:W32/PoisonIvy gives the attacker practically complete control over the infected computer. Exact functionality depends on the variant in question but the following are the most common operations available to the attacker. Operations:
* Files can be renamed, deleted, or executed. Files can also be uploaded and downloaded to and from the system;
* The Windows registry can be viewed and edited;
* Currently running processes can be viewed and suspended or killed;
* Current network connections can be viewed and shut down
* Services can be viewed and controlled (for example stopped or started);
* Installed devices can be viewed and some devices can be disabled;
* The list of installed applications can be viewed and entries can be deleted or programs uninstalled;


Other functionality includes viewing a list of open windows or starting a remote command shell on the infected computer. Poison Ivy variants can also steal information by taking screenshots of the desktop and recording audio or webcam footage. They can also access saved passwords and password hashes.
Some variants also have a keylogger. Additional features not provided by the Poison Ivy configuration kit can be added by third party plugins.

### ServHelper

ServHelper is a recently discovered backdoor associated with TA505. A veteran threat group that has also been associated with the infamous Dridex banking malware, the GlobeIimposter ransomware, and other high-profile malware campaigns.

Once the malicious Excel sheet is opened the Excel 4.0 macro is executed and msiexec.exe is called in order to download and execute the payload. ServHelper’s payload, an NSIS Installer signed with a valid digital signature (further details on the certificate ahead), is downloaded by msiexec.exe to its temporary folder (C:\Windows\Installer\MSI<4-charachter-string>.tmp) and executed.
Once the dropped payload is executed, it will drop a DLL file contained in the installer to \%TEMP%\xmlparse.dll, and use rundll32.exe to call the DLL’s exported function “sega”. The malware will then write a base64 encoded PowerShell script (which is contained in xmlparse.dll as a resource) to \%TEMP%\enu1.ps1 and execute it. The script, intended for reconnaissance purposes, checks if a machine is part of a domain and if the user has Admin privileges or is part of the Admin Group. This information is then reported back to ServHelper’s Command & Control server and if the user is part of a domain, the Command & Control server will also instruct the malware to gather a list of other users in the domain.

<div style="text-align:center;"><img src="https://www.deepinstinct.com/image/blt1c48528ce3e3a20f/611a8046ecfcb7167c21b247/flow.png" /></div>

ServHelper can receive several types of commands from its Command & Control server, including:
* **shell**: execute a shell (cmd.exe) command and return its output;
* **loadll**: download a DLL file and load it using rundll32.exe;
* **persist**: write an auto-run registry entry at *HK_CU\Software\Microsoft\Windows\CurrentVersion\Run* as “Intel Protect”, returns “persistence established” if successful;
* **sleep**: enter sleep mode;
* **selfkill**: remove the malware from the infected machine;