class NXCModule:
    name = "presence"
    description = "Traces Domain and Enterprise Admin presence in the target over SMB"
    supported_protocols = ["smb"]
    opsec_safe = False
    multiple_hosts = False

    def options(self, context, module_options):
        """There are no module options."""

    def on_login(self, context, connection):
        admin_users = set()
        
        # Get the NetBIOS name of the target machine
        netbios_name = self.get_netbios_name(context, connection)
        context.log.debug(f"Target NetBIOS Name: {netbios_name}")

        # Run 'net group "Domain Admins" /domain' and 'net group "Enterprise Admins" /domain'
        for group in ["Domain Admins", "Enterprise Admins"]:
            command = f'net group "{group}" /domain'
            output = connection.execute(command, True, methods=["smbexec"])
            context.log.debug(f"Raw output for {group}: {output}")
            
            if output:
                admin_users.update(self.parse_admins(output))
            else:
                context.log.error(f"Failed to retrieve {group} members")
        
        if not admin_users:
            context.log.error("No admin users found, stopping execution.")
            return False

        context.log.success(f"Identified Admin Users: {', '.join(admin_users)}")
        
        # Check C:\\Users\\ for presence of admin accounts
        matched_dirs = self.check_users_directory(context, connection, admin_users)
        
        # Execute 'tasklist /v' and search for admin users
        matched_tasks = self.check_tasklist(context, connection, admin_users, netbios_name)
        
        if not matched_dirs and not matched_tasks:
            context.log.success("No matches found in users directory or tasklist.")
        
        return True

    def get_netbios_name(self, context, connection):
        """Retrieves the NetBIOS name of the target machine."""
        command = "hostname"
        output = connection.execute(command, True, methods=["smbexec"]).strip()
        return output if output else None
    
    def parse_admins(self, output):
        """Extracts admin usernames from 'net group' command output."""
        lines = output.splitlines()
        users = set()

        capture = False
        for line in lines:
            line = line.strip()

            # Start capturing after 'Members' line
            if "Members" in line:
                capture = True
                continue

            # Stop capturing if we reach a footer or empty line
            if not line or "The command completed successfully" in line:
                break

            if capture and not any(keyword in line for keyword in ["---", "Group name", "Comment"]):
                # Split line into words, take each as a username
                for user in line.split():
                    users.add(user)

        return users
    
    def check_users_directory(self, context, connection, admin_users):
        """Checks if identified admin users have directories in C:\\Users\\, ensuring only dotted Administrator formats."""
        command = 'dir C:\\Users'
        output = connection.execute(command, True, methods=["smbexec"])
        context.log.debug(f"Raw output for user directories:\n{output}")

        matched_dirs = []

        for line in output.splitlines():
            parts = line.split()  # Split line by spaces
            if len(parts) > 3:
                folder_name = parts[-1]

                # Ensure Administrator is only included if it has a dotted prefix
                if folder_name.endswith(".Administrator") and folder_name != "Administrator":
                    matched_dirs.append(folder_name)
                
                # Check for exact match or dotted variations for other admin users
                for user in admin_users:
                    if user != "Administrator" and (folder_name == user or folder_name.endswith(f".{user}")):
                        matched_dirs.append(folder_name)

        if matched_dirs:
            context.log.success(f"Found user directories: {', '.join(matched_dirs)}")
        else:
            context.log.info("No matching directories found in C:\\Users\\")

        return matched_dirs

    def check_tasklist(self, context, connection, admin_users, netbios_name):
        """Checks 'tasklist /v' output for admin user presence, excluding local machine Administrator."""
        command = 'tasklist /v'
        output = connection.execute(command, True, methods=["smbexec"])
        context.log.debug(f"Raw output for tasklist:\n{output}")

        matched_tasks = []

        for user in admin_users:
            if user == "Administrator":
                # Exclude NETBIOS\Administrator
                admin_pattern = fr"(?i)^(?!.*{re.escape(netbios_name)}\\Administrator\b).*\\Administrator\b"
                if re.search(admin_pattern, output, re.MULTILINE):
                    matched_tasks.append("Administrator")
            else:
                if user in output:
                    matched_tasks.append(user)

        if matched_tasks:
            context.log.success(f"Found users in tasklist: {', '.join(matched_tasks)}")
        else:
            context.log.info("No admin users found in running processes.")

        return matched_tasks
