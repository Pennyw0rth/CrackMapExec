class NXCModule:
    """Enables or disables xp_cmdshell in MSSQL Server."""

    name = "enable_cmdshell"
    description = "Enables or disables xp_cmdshell in MSSQL Server"
    supported_protocols = ["mssql"]
    opsec_safe = False
    multiple_hosts = True

    def __init__(self):
        self.mssql_conn = None
        self.context = None
        self.action = None

    def options(self, context, module_options):
        """
        Available options:
        - ACTION: enable or disable xp_cmdshell
        Example usage:
        netexec mssql $TARGET -u $username -p $password -M enable_cmdshell -o ACTION=enable
        netexec mssql $TARGET -u $username -p $password -M enable_cmdshell -o ACTION=disable
        """
        if "ACTION" in module_options:
            self.action = module_options["ACTION"].lower()
        else:
            context.log.error("Missing required option: ACTION (enable/disable)")

    def on_login(self, context, connection):
        self.context = context
        self.mssql_conn = connection.conn

        if self.action == "enable":
            self.toggle_xp_cmdshell(enable=True)
        elif self.action == "disable":
            self.toggle_xp_cmdshell(enable=False)
        else:
            self.context.log.error("Invalid ACTION. Use 'enable' or 'disable'.")

    def toggle_xp_cmdshell(self, enable: bool):
        """Enables or disables xp_cmdshell."""
        state = "1" if enable else "0"
        commands = [
            "EXEC sp_configure 'show advanced options', '1'",
            "RECONFIGURE",
            f"EXEC sp_configure 'xp_cmdshell', '{state}'",
            "RECONFIGURE"
        ]

        for cmd in commands:
            try:
                self.mssql_conn.sql_query(cmd)
            except Exception as e:
                self.context.log.error(f"Failed to execute command: {e}")
                return

        action_text = "enabled" if enable else "disabled"
        self.context.log.success(f"xp_cmdshell successfully {action_text}.")
