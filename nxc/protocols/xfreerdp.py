import os
import re
import sys
import uuid
import subprocess

from datetime import datetime
from termcolor import colored

from nxc.connection import connection
from nxc.logger import NXCAdapter
from nxc.config import process_secret
from nxc.config import host_info_colors

success_flag = "Authentication only, exit status 0"

status_dict = {
    "(Account has been locked)": ["ERRCONNECT_ACCOUNT_LOCKED_OUT"],
    "(Account has been disabled)": ["ERRCONNECT_ACCOUNT_DISABLED [0x00020012]"],
    "(Account was expired)": ["0x0002000D", "0x00000009"], 
    "(Not support NLA)": ["ERRCONNECT_SECURITY_NEGO_CONNECT_FAILED [0x0002000C]"],
    "(Password expired)": ["0x0002000E", "0x0002000F", "0x00020013"],
    "(RDP login failed)": ["0x00020009", "0x00020014"],
    "Failed": ["Resource temporarily unavailable", "Broken pipe", "ERRCONNECT_CONNECT_FAILED [0x00020006]", "Connection timed out", "Connection reset by peer"]
}

class xfreerdp(connection):

    def __init__(self, args, db, host):
        self.output_filename = None
        self.domain = None
        self.nla = False

        connection.__init__(self, args, db, host)

    def proto_logger(self):
        self.logger = NXCAdapter(
            extra={
                "protocol": "XFREERDP",
                "host": self.host,
                "port": self.port,
                "hostname": self.hostname,
            }
        )
    
    def print_host_info(self):
        nla = colored(f"nla:{self.nla}", host_info_colors[3], attrs=["bold"]) if self.nla else colored(f"nla:{self.nla}", host_info_colors[2], attrs=["bold"])
        if not self.nla:
            self.logger.display(f"Old version OS which means not support NLA (name:{self.host}) {nla}")
        else:
            self.logger.display(f"(name:{self.hostname}) {nla}")
        return True

    def create_conn_obj(self):
        if not os.getenv("DISPLAY"):
            self.logger.fail("Run xfreerdp failed, please check the $DISPLAY environment variable. (for more details, please check https://github.com/FreeRDP/FreeRDP/issues/7129)")
            sys.exit(1)
        try:
            connection = subprocess.Popen(f'xfreerdp /v:"{self.host}" /port:{self.port} +auth-only /d:"{uuid.uuid4()!s}" /u:"{uuid.uuid4()!s}" /p:"{uuid.uuid4()!s}" /cert:tofu /tls-seclevel:0 /timeout:{self.args.rdp_timeout * 1000}', stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
            # For New/Old certificate, /cert-tofu can't handle it.
            connection.stdin.write(b"Y\n")
            connection.stdin.flush()
            output_error = connection.stderr.read().decode("utf-8")
            if any(single_word in output_error for single_word in status_dict["Failed"]):
                return False
            else:
                CN_match = re.search(r"CN = (\S+)", output_error)
                if CN_match:
                    hostname = CN_match.group(1)
                    self.nla = True
                    self.hostname = hostname
                    self.logger.extra["hostname"] = hostname
                else:
                    self.logger.extra["hostname"] = self.host

                self.output_filename = os.path.expanduser(f"~/.cme/logs/{self.hostname}_{self.host}_{datetime.now().strftime('%Y-%m-%d_%H%M%S')}".replace(":", "-"))

                if self.args.domain:
                    self.domain = self.args.domain

                if self.args.local_auth:
                    self.domain = self.hostname

                return True
        except Exception as e:
            self.logger.error(str(e))
        return False
    
    def plaintext_login(self, domain, username, password):
        self.domain = domain
        self.username = username
        self.password = password
        try:
            connection = subprocess.Popen(f'xfreerdp /v:"{self.host}" /port:{self.port} +auth-only /d:"{self.domain}" /u:"{self.username}" /p:"{self.password}" /cert:ignore /tls-seclevel:0 /timeout:{self.args.rdp_timeout * 1000}', stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
            output_error = connection.stderr.read().decode("utf-8")
            if success_flag in output_error:
                self.admin_privs = True
                self.logger.success(f"{self.domain}\\{self.username}:{process_secret(self.password)} {self.mark_pwned()}")
            else:
                for k, v in status_dict.items():
                    if any(single_word in output_error for single_word in v):
                        self.logger.fail(f"{self.domain}\\{self.username}:{process_secret(self.password)} {k}")
                        return False

            if not self.args.continue_on_success:
                return True
        
        except Exception as e:
            self.logger.error(str(e))

    def hash_login(self, domain, username, ntlm_hash):
        self.domain = domain
        self.username = username
        if ntlm_hash.find(":") != -1:
            self.logger.info("RDP with PTH not support LM hash, will not use LM hash")
            _, self.nthash = ntlm_hash.split(":")
        else:
            self.nthash = ntlm_hash
        try:
            connection = subprocess.Popen(f'xfreerdp /v:"{self.host}" /port:{self.port} +auth-only /d:"{self.domain}" /u:"{self.username}" /p:"" /pth:{self.nthash} /sec:nla /cert:ignore /tls-seclevel:0 /timeout:{self.args.rdp_timeout * 1000}', stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
            output_error = connection.stderr.read().decode("utf-8")
            if success_flag in output_error:
                self.admin_privs = True
                self.logger.success(f"{self.domain}\\{self.username}:{process_secret(self.nthash)} {self.mark_pwned()}")
            else:
                for k, v in status_dict.items():
                    if any(single_word in output_error for single_word in v):
                        self.logger.fail(f"{self.domain}\\{self.username}:{process_secret(self.nthash)} {k}")
                        return False

            if not self.args.continue_on_success:
                return True
        
        except Exception as e:
            self.logger.error(str(e))