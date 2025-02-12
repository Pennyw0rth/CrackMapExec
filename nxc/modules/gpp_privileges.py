import ssl
import ldap3
import re
from io import BytesIO


class NXCModule:
    """
    Module to retrieve privileges assigned via Group Policy Objects (GPOs) by parsing GptTmpl.inf files
    and resolving SIDs using LDAP.
    """

    name = "gpp_privileges"
    description = "Extracts privileges assigned via GPOs and resolves SIDs via LDAP."
    supported_protocols = ["smb"]
    opsec_safe = True
    multiple_hosts = True

    WELL_KNOWN_SIDS = {
    "S-1-0": "Null Authority",
    "S-1-0-0": "Nobody",
    "S-1-1": "World Authority",
    "S-1-1-0": "Everyone",
    "S-1-2": "Local Authority",
    "S-1-2-0": "Local",
    "S-1-2-1": "Console Logon",
    "S-1-3": "Creator Authority",
    "S-1-3-0": "Creator Owner",
    "S-1-3-1": "Creator Group",
    "S-1-3-2": "Creator Owner Server",
    "S-1-3-3": "Creator Group Server",
    "S-1-3-4": "Owner Rights",
    "S-1-5-80-0": "All Services",
    "S-1-4": "Non-unique Authority",
    "S-1-5": "NT Authority",
    "S-1-5-1": "Dialup",
    "S-1-5-2": "Network",
    "S-1-5-3": "Batch",
    "S-1-5-4": "Interactive",
    "S-1-5-6": "Service",
    "S-1-5-7": "Anonymous",
    "S-1-5-8": "Proxy",
    "S-1-5-9": "Enterprise Domain Controllers",
    "S-1-5-10": "Principal Self",
    "S-1-5-11": "Authenticated Users",
    "S-1-5-12": "Restricted Code",
    "S-1-5-13": "Terminal Server Users",
    "S-1-5-14": "Remote Interactive Logon",
    "S-1-5-15": "This Organization",
    "S-1-5-17": "This Organization",
    "S-1-5-18": "Local System",
    "S-1-5-19": "NT Authority",
    "S-1-5-20": "NT Authority",
    "S-1-5-32-544": "Administrators",
    "S-1-5-32-545": "Users",
    "S-1-5-32-546": "Guests",
    "S-1-5-32-547": "Power Users",
    "S-1-5-32-548": "Account Operators",
    "S-1-5-32-549": "Server Operators",
    "S-1-5-32-550": "Print Operators",
    "S-1-5-32-551": "Backup Operators",
    "S-1-5-32-552": "Replicators",
    "S-1-5-64-10": "NTLM Authentication",
    "S-1-5-64-14": "SChannel Authentication",
    "S-1-5-64-21": "Digest Authority",
    "S-1-5-80": "NT Service",
    "S-1-5-83-0": "NT VIRTUAL MACHINE\\Virtual Machines",
    "S-1-16-0": "Untrusted Mandatory Level",
    "S-1-16-4096": "Low Mandatory Level",
    "S-1-16-8192": "Medium Mandatory Level",
    "S-1-16-8448": "Medium Plus Mandatory Level",
    "S-1-16-12288": "High Mandatory Level",
    "S-1-16-16384": "System Mandatory Level",
    "S-1-16-20480": "Protected Process Mandatory Level",
    "S-1-16-28672": "Secure Process Mandatory Level",
    "S-1-5-32-554": "BUILTIN\\Pre-Windows 2000 Compatible Access",
    "S-1-5-32-555": "BUILTIN\\Remote Desktop Users",
    "S-1-5-32-557": "BUILTIN\\Incoming Forest Trust Builders",
    "S-1-5-32-556": "BUILTIN\\Network Configuration Operators",
    "S-1-5-32-558": "BUILTIN\\Performance Monitor Users",
    "S-1-5-32-559": "BUILTIN\\Performance Log Users",
    "S-1-5-32-560": "BUILTIN\\Windows Authorization Access Group",
    "S-1-5-32-561": "BUILTIN\\Terminal Server License Servers",
    "S-1-5-32-562": "BUILTIN\\Distributed COM Users",
    "S-1-5-32-569": "BUILTIN\\Cryptographic Operators",
    "S-1-5-32-573": "BUILTIN\\Event Log Readers",
    "S-1-5-32-574": "BUILTIN\\Certificate Service DCOM Access",
    "S-1-5-32-575": "BUILTIN\\RDS Remote Access Servers",
    "S-1-5-32-576": "BUILTIN\\RDS Endpoint Servers",
    "S-1-5-32-577": "BUILTIN\\RDS Management Servers",
    "S-1-5-32-578": "BUILTIN\\Hyper-V Administrators",
    "S-1-5-32-579": "BUILTIN\\Access Control Assistance Operators",
    "S-1-5-32-580": "BUILTIN\\Remote Management Users",
}

    def options(self, context, module_options):
        """
        Define module options.
        - no_ldap: If set to True, disables LDAP queries for resolving SIDs.
        """
        self.no_ldap = module_options.get("NO_LDAP", False)

    def on_login(self, context, connection):
        shares = connection.shares()
        for share in shares:
            if share["name"] == "SYSVOL" and "READ" in share["access"]:
                context.log.info("Found SYSVOL share")
                context.log.display("Searching for GptTmpl.inf files")

                paths = connection.spider("SYSVOL", pattern=["GptTmpl.inf"])

                if not paths:
                    context.log.warning("No GptTmpl.inf files found in SYSVOL.")
                    return

                for path in paths:
                    if "6AC1786C-016F-11D2-945F-00C04fB984F9" in path:  # Default Domain Policy
                        context.log.success(f"Found Default Domain Policy GptTmpl.inf: {path}")
                    else:
                        context.log.info(f"Found GptTmpl.inf: {path}")

                    buf = BytesIO()
                    connection.conn.getFile("SYSVOL", path, buf.write)

                    try:
                        content = buf.getvalue().decode("utf-16le")
                    except UnicodeDecodeError as e:
                        context.log.error(f"Failed to decode {path} as UTF-16LE: {e}")
                        continue

                    privileges = self.extract_privileges(content)
                    if privileges:
                        ldap_connection = None
                        if not self.no_ldap:
                            ldap_connection = self.initialize_ldap_connection(context, connection)

                        context.log.success(f"Privileges extracted from {path}:")
                        for privilege, sids in privileges.items():
                            resolved_sids = [
                                self.resolve_sid(context, sid, ldap_connection) for sid in sids
                            ]
                            context.log.highlight(f"{privilege}: {', '.join(resolved_sids)}")

                        if ldap_connection:
                            ldap_connection.unbind()

    def extract_privileges(self, content):
        """Parses the content of GptTmpl.inf to extract privilege rights."""
        privileges = {}
        in_priv_section = False

        for line in content.splitlines():
            if line.strip() == "[Privilege Rights]":
                in_priv_section = True
                continue
            if in_priv_section and line.strip() == "":
                break
            if in_priv_section:
                match = re.match(r"^(.*?)\s*=\s*(.*)$", line)
                if match:
                    privilege, sids = match.groups()
                    privileges[privilege] = [sid.strip("*") for sid in sids.split(",")]

        return privileges

    def initialize_ldap_connection(self, context, connection):
        """
        Initializes an LDAP connection using LDAP3 with LDAPS first, then falls back to plaintext LDAP if LDAPS fails.
        Attempts to retrieve the base DN from the Root DSE or derive it from the domain name.
        """
        tls = ldap3.Tls(validate=ssl.CERT_NONE, version=ssl.PROTOCOL_TLSv1_2, ciphers="ALL:@SECLEVEL=0")
        base_dn = None

        try:
            ldap_server = ldap3.Server(connection.host, use_ssl=True, port=636, tls=tls)
            ldap_connection = ldap3.Connection(
                ldap_server,
                user=f"{connection.domain}\\{connection.username}",
                password=connection.password,
                authentication=ldap3.NTLM,
                raise_exceptions=True,
            )
            ldap_connection.bind()
            context.log.success("Connected to LDAP over SSL (LDAPS).")

            try:
                ldap_connection.search(
                    search_base="",
                    search_filter="(objectClass=*)",
                    search_scope=ldap3.BASE,
                    attributes=["defaultNamingContext"],
                )
                if ldap_connection.entries:
                    base_dn = ldap_connection.entries[0]["defaultNamingContext"].value
                    context.log.success(f"Retrieved base DN over LDAPS: {base_dn}")
                else:
                    context.log.warning("defaultNamingContext not found in Root DSE. Falling back to domain name derivation.")
            except Exception as e:
                context.log.warning(f"Failed to query Root DSE for defaultNamingContext over LDAPS: {e}")

            if not base_dn:
                domain_parts = connection.domain.split(".")
                base_dn = ",".join([f"dc={part}" for part in domain_parts])
                context.log.info(f"Derived base DN: {base_dn}")

            ldap_connection.base_dn = base_dn
            return ldap_connection

        except Exception as ldaps_error:
            context.log.warning(f"LDAPS connection failed: {ldaps_error}")
            context.log.info("Falling back to plain LDAP...")

        try:
            ldap_server = ldap3.Server(connection.host, use_ssl=False, port=389)
            ldap_connection = ldap3.Connection(
                ldap_server,
                user=f"{connection.domain}\\{connection.username}",
                password=connection.password,
                authentication=ldap3.NTLM,
                raise_exceptions=True,
            )
            ldap_connection.bind()
            context.log.info("Connected to LDAP successfully (plaintext).")

            try:
                ldap_connection.search(
                    search_base="",
                    search_filter="(objectClass=*)",
                    search_scope=ldap3.BASE,
                    attributes=["defaultNamingContext"],
                )
                if ldap_connection.entries:
                    base_dn = ldap_connection.entries[0]["defaultNamingContext"].value
                    context.log.success(f"Retrieved base DN over plain LDAP: {base_dn}")
                else:
                    context.log.warning("defaultNamingContext not found in Root DSE. Falling back to domain name derivation.")
            except Exception as e:
                context.log.warning(f"Failed to query Root DSE for defaultNamingContext over plain LDAP: {e}")

            if not base_dn:
                domain_parts = connection.domain.split(".")
                base_dn = ",".join([f"dc={part}" for part in domain_parts])
                context.log.info(f"Derived base DN: {base_dn}")

            ldap_connection.base_dn = base_dn
            return ldap_connection

        except Exception as ldap_error:
            context.log.error(f"Failed to connect to LDAP: {ldap_error}")

        return None




    def resolve_sid(self, context, sid, ldap_connection):
        """Resolves a SID to a human-readable name using well-known mappings or LDAP queries."""
        if sid in self.WELL_KNOWN_SIDS:
            return self.WELL_KNOWN_SIDS[sid]

        if ldap_connection and ldap_connection.bound:
            try:
                base_dn = getattr(ldap_connection, "base_dn", None)
                if not base_dn:
                    context.log.warning(f"No base DN found for LDAP connection. Cannot resolve SID {sid}.")
                    return sid

                search_filter = f"(objectSid={ldap3.utils.conv.escape_filter_chars(sid)})"
                ldap_connection.search(
                    search_base=base_dn,
                    search_filter=search_filter,
                    attributes=["sAMAccountName"],
                )

                if ldap_connection.entries:
                    entry = ldap_connection.entries[0]
                    return f"{entry['sAMAccountName']}"
                else:
                    context.log.warning(f"SID {sid} not found in LDAP. Returning raw SID.")

            except Exception as e:
                context.log.error(f"Failed to resolve SID {sid} via LDAP: {e}")
        else:
            context.log.warning(f"LDAP connection not established or unbound. Returning raw SID: {sid}")

        return sid

    