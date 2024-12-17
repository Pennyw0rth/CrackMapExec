import pylnk3
from io import BytesIO


class NXCModule:
    # Get a list of recently modified files via LNK's stored in AppData\Roaming\Microsoft\Windows\Recent
    # Module by @Defte_

    name = "recent_files"
    description = "Extracts recently modified files"
    supported_protocols = ["smb"]
    opsec_safe = True
    multiple_hosts = True
    false_positive = [".", "..", "desktop.ini", "Public", "Default", "Default User", "All Users", ".NET v4.5", ".NET v4.5 Classic"]

    def options(self, context, module_options):
        """"""

    def on_admin_login(self, context, connection):
        lnks = []
        for directory in connection.conn.listPath("C$",  "Users\\*"):
            if directory.get_longname() not in self.false_positive and directory.is_directory():
                context.log.highlight(f"C:\\{directory.get_longname()}")
                recent_files_dir = f"Users\\{directory.get_longname()}\\AppData\\Roaming\\Microsoft\\Windows\\Recent\\"
                for file in connection.conn.listPath("C$", f"{recent_files_dir}\\*"):
                    file_path = f"{recent_files_dir}{file.get_longname()}"
                    if file.get_longname() not in self.false_positive and not file.is_directory():
                        file_path = f"{recent_files_dir}{file.get_longname()}"
                        try:
                            buf = BytesIO()
                            connection.conn.getFile("C$", file_path, buf.write)
                            buf.seek(0)
                            lnk = pylnk3.parse(buf).path.strip()
                            if lnk and lnk not in lnks:
                                context.log.highlight(f"\t{lnk}")
                                lnks.append(lnk)
                        except Exception as e:
                            # Sometimes PyLnk3 can't parse the lnk file...
                            context.log.debug(f"Couldn't open {file_path} because of {e}")
