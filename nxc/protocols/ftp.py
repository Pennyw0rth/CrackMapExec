import os
from nxc.config import process_secret
from nxc.connection import connection
from nxc.helpers.logger import highlight
from nxc.logger import NXCAdapter
from ftplib import FTP, error_perm

class ftp(connection):
    def __init__(self, args, db, host):
        self.protocol = "FTP"
        self.remote_version = None

        super().__init__(args, db, host)

    def proto_logger(self):
        self.logger = NXCAdapter(
            extra={
                "protocol": "FTP",
                "host": self.host,
                "port": self.port,
                "hostname": self.hostname,
            }
        )

    def proto_flow(self):
        self.proto_logger()
        if self.create_conn_obj() and self.login():
            if hasattr(self.args, "module") and self.args.module:
                self.load_modules()
                self.logger.debug("Calling modules")
                self.call_modules()
            else:
                self.logger.debug("Calling command arguments")
                self.call_cmd_args()

    def enum_host_info(self):
        welcome = self.conn.getwelcome()
        self.logger.debug(f"Welcome result: {welcome}")
        self.remote_version = welcome.split("220", 1)[1].strip()  # strip out the extra space in the front
        self.logger.debug(f"Remote version: {self.remote_version}")

    def print_host_info(self):
        self.logger.display(f"Banner: {self.remote_version}")

    def create_conn_obj(self):
        self.conn = FTP()
        try:
            self.conn.connect(host=self.host, port=self.port)
        except Exception as e:
            self.logger.debug(f"Error connecting to FTP host: {e}")
            return False
        return True

    def plaintext_login(self, username, password):
        if not self.conn.sock:
            self.create_conn_obj()
        try:
            self.logger.debug(self.conn.sock)
            resp = self.conn.login(user=username, passwd=password)
            self.logger.debug(f"Response: {resp}")
        except Exception as e:
            self.logger.fail(f"{username}:{process_secret(password)} (Response:{e})")
            self.conn.close()
            return False

        # 230 is "User logged in, proceed" response, ftplib raises an exception on failed login
        if "230" in resp:
            self.logger.debug(f"Host: {self.host} Port: {self.port}")
            self.db.add_host(self.host, self.port, self.remote_version)

            cred_id = self.db.add_credential(username, password)

            host_id = self.db.get_hosts(self.host)[0].id
            self.db.add_loggedin_relation(cred_id, host_id)

            if username in ["anonymous", ""]:
                self.logger.success(f"{username}:{process_secret(password)} {highlight('- Anonymous Login!')}")
            else:
                self.logger.success(f"{username}:{process_secret(password)}")

        if self.args.ls:
            # If the default directory is specified, then we will list the current directory
            if self.args.ls == ".":
                files = self.list_directory_full()
                # If files is false, then we encountered an exception
                if not files:
                    return False
                # If there are files, then we can list the files
                self.logger.display("Directory Listing")
                for file in files:
                    self.logger.highlight(file)
            else:
                # If the default directory is not specified, then we will list the specified directory
                self.logger.display(f"Directory Listing for {self.args.ls}")
                # Change to the specified directory
                try:
                    self.conn.cwd(self.args.ls)
                except error_perm as error_message:
                    self.logger.fail(f"Failed to change directory. Response: ({error_message})")
                    self.conn.close()
                    return False
                # List the files in the specified directory
                files = self.list_directory_full()
                for file in files:
                    self.logger.highlight(file)

        if self.args.get:
            self.get_file(f"{self.args.get}")

        if self.args.put:
            self.put_file(self.args.put[0], self.args.put[1])

        if not self.args.continue_on_success:
            self.conn.close()
            return True
        self.conn.close()

    def list_directory_full(self):
        # in the future we can use mlsd/nlst if we want, but this gives a full output like `ls -la`
        # ftplib's "dir" prints directly to stdout, and "nlst" only returns the folder name, not full details
        files = []
        try:
            self.conn.retrlines("LIST", callback=files.append)
        except error_perm as error_message:
            self.logger.fail(f"Failed to list directory. Response: ({error_message})")
            self.conn.close()
            return False
        return files

    def get_file(self, filename):
        # Extract the filename from the path
        downloaded_file = filename.split("/")[-1]
        try:
            # Check if the current connection is ASCII (ASCII does not support .size())
            if self.conn.encoding == "utf-8":
                # Switch the connection to binary
                self.conn.sendcmd("TYPE I")
            # Check if the file exists 
            self.conn.size(filename)
            # Attempt to download the file
            self.conn.retrbinary(f"RETR {filename}", open(downloaded_file, "wb").write)  # noqa: SIM115
        except error_perm as error_message:
            self.logger.fail(f"Failed to download the file. Response: ({error_message})")
            self.conn.close()
            return False
        except FileNotFoundError:
            self.logger.fail("Failed to download the file. Response: (No such file or directory.)")
            self.conn.close()
            return False
        # Check if the file was downloaded
        if os.path.isfile(downloaded_file):
            self.logger.success(f"Downloaded: {filename}")
        else:
            self.logger.fail(f"Failed to download: {filename}")

    def put_file(self, local_file, remote_file):
        try:
            # Check if the remote file already exists
            self.conn.voidcmd("TYPE I")  # Switch to binary mode. necessary for size command.
            if self.conn.size(remote_file) is not None:
                ans = input(highlight(f"[!] {remote_file} already exists. Do you want to overwrite it? [Y/n] ", "red"))
                if ans.lower() not in ["y", "yes", ""]:
                    self.logger.fail(f"Uploading was not successful. The file {remote_file} already exists.")
                    return False
                self.logger.display(f"Trying to overwrite {remote_file}...")

        except error_perm:
            # If file does not exist, an error_perm will be raised, continue with upload
            pass
        except Exception as e:
            self.logger.fail(f"Error checking if remote file exists: {e}")
            return False

        try:
            # Attempt to upload the file
            with open(local_file, "rb") as file:
                self.conn.storbinary(f"STOR {remote_file}", file)
        except error_perm as error_message:
            self.logger.fail(f"Failed to upload file. Response: ({error_message})")
            return False
        except FileNotFoundError:
            self.logger.fail(f"Failed to upload file. {local_file} does not exist locally.")
            return False

        # Check if the file was uploaded successfully
        if self.conn.size(remote_file) > 0:
            self.logger.success(f"Uploaded: {local_file} to {remote_file}")
        else:
            self.logger.fail(f"Failed to upload: {local_file} to {remote_file}")

    def supported_commands(self):
        raw_supported_commands = self.conn.sendcmd("HELP")
        supported_commands = [item for sublist in (x.split() for x in raw_supported_commands.split("\n")[1:-1]) for item in sublist]
        self.logger.debug(f"Supported commands: {supported_commands}")
        return supported_commands
