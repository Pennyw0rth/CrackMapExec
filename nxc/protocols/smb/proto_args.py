from argparse import _StoreTrueAction
from nxc.helpers.args import DisplayDefaultsNotNone, DefaultTrackingAction


def proto_args(parser, parents):
    smb_parser = parser.add_parser("smb", help="own stuff using SMB", parents=parents, formatter_class=DisplayDefaultsNotNone)
    smb_parser.add_argument("-H", "--hash", metavar="HASH", dest="hash", nargs="+", default=[], help="NTLM hash(es) or file(s) containing NTLM hashes")

    delegate_arg = smb_parser.add_argument("--delegate", action="store", help="Impersonate user with S4U2Self + S4U2Proxy")
    self_delegate_arg = smb_parser.add_argument("--self", dest="no_s4u2proxy", action=get_conditional_action(_StoreTrueAction), make_required=[], help="Only do S4U2Self, no S4U2Proxy (use with delegate)")

    dgroup = smb_parser.add_mutually_exclusive_group()
    dgroup.add_argument("-d", "--domain", metavar="DOMAIN", dest="domain", type=str, help="domain to authenticate to")
    dgroup.add_argument("--local-auth", action="store_true", help="authenticate locally to each target")

    smb_parser.add_argument("--port", type=int, default=445, help="SMB port")
    smb_parser.add_argument("--share", metavar="SHARE", default="C$", help="specify a share")
    smb_parser.add_argument("--smb-server-port", default="445", help="specify a server port for SMB", type=int)
    smb_parser.add_argument("--no-smbv1", action="store_true", help="Force to disable SMBv1 in connection")
    smb_parser.add_argument("--gen-relay-list", metavar="OUTPUT_FILE", help="outputs all hosts that don't require SMB signing to the specified file")
    smb_parser.add_argument("--smb-timeout", help="SMB connection timeout", type=int, default=2)
    smb_parser.add_argument("--laps", dest="laps", metavar="LAPS", type=str, help="LAPS authentification", nargs="?", const="administrator")
    smb_parser.add_argument("--generate-hosts-file", type=str, help="Generate a hosts file like from a range of IP")
    smb_parser.add_argument("--generate-krb5-file", type=str, help="Generate a krb5 file like from a range of IP")
    self_delegate_arg.make_required = [delegate_arg]

    cred_gathering_group = smb_parser.add_argument_group("Credential Gathering", "Options for gathering credentials")
    cred_gathering_group.add_argument("--sam", action="store_true", help="dump SAM hashes from target systems")
    cred_gathering_group.add_argument("--lsa", action="store_true", help="dump LSA secrets from target systems")
    cred_gathering_group.add_argument("--ntds", choices={"vss", "drsuapi"}, nargs="?", const="drsuapi", help="dump the NTDS.dit from target DCs using the specifed method")
    cred_gathering_group.add_argument("--dpapi", choices={"cookies", "nosystem"}, nargs="*", help="dump DPAPI secrets from target systems, can dump cookies if you add 'cookies', will not dump SYSTEM dpapi if you add nosystem")
    cred_gathering_group.add_argument("--sccm", choices={"wmi", "disk"}, nargs="?", const="disk", help="dump SCCM secrets from target systems")
    cred_gathering_group.add_argument("--mkfile", action="store", help="DPAPI option. File with masterkeys in form of {GUID}:SHA1")
    cred_gathering_group.add_argument("--pvk", action="store", help="DPAPI option. File with domain backupkey")
    cred_gathering_group.add_argument("--enabled", action="store_true", help="Only dump enabled targets from DC")
    cred_gathering_group.add_argument("--user", dest="userntds", type=str, help="Dump selected user from DC")

    mapping_enum_group = smb_parser.add_argument_group("Mapping/Enumeration", "Options for Mapping/Enumerating")
    mapping_enum_group.add_argument("--shares", action="store_true", help="enumerate shares and access")
    mapping_enum_group.add_argument("--dir", nargs="?", type=str, const="", help="List the content of a path (default path: '%(const)s')")
    mapping_enum_group.add_argument("--interfaces", action="store_true", help="enumerate network interfaces")
    mapping_enum_group.add_argument("--no-write-check", action="store_true", help="Skip write check on shares (avoid leaving traces when missing delete permissions)")
    mapping_enum_group.add_argument("--filter-shares", nargs="+", help="Filter share by access, option 'read' 'write' or 'read,write'")
    mapping_enum_group.add_argument("--sessions", action="store_true", help="enumerate active sessions")
    mapping_enum_group.add_argument("--disks", action="store_true", help="enumerate disks")
    mapping_enum_group.add_argument("--loggedon-users-filter", action="store", help="only search for specific user, works with regex")
    mapping_enum_group.add_argument("--loggedon-users", action="store_true", help="enumerate logged on users")
    mapping_enum_group.add_argument("--users", nargs="*", metavar="USER", help="enumerate domain users, if a user is specified than only its information is queried.")
    mapping_enum_group.add_argument("--groups", nargs="?", const="", metavar="GROUP", help="enumerate domain groups, if a group is specified than its members are enumerated")
    mapping_enum_group.add_argument("--computers", nargs="?", const="", metavar="COMPUTER", help="enumerate computer users")
    mapping_enum_group.add_argument("--local-groups", nargs="?", const="", metavar="GROUP", help="enumerate local groups, if a group is specified then its members are enumerated")
    mapping_enum_group.add_argument("--pass-pol", action="store_true", help="dump password policy")
    mapping_enum_group.add_argument("--rid-brute", nargs="?", type=int, const=4000, metavar="MAX_RID", help="enumerate users by bruteforcing RIDs")

    wmi_group = smb_parser.add_argument_group("WMI", "Options for WMI Queries")
    wmi_group.add_argument("--wmi", metavar="QUERY", type=str, help="issues the specified WMI query")
    wmi_group.add_argument("--wmi-namespace", metavar="NAMESPACE", default="root\\cimv2", help="WMI Namespace")

    spidering_group = smb_parser.add_argument_group("Spidering", "Options for spidering shares")
    spidering_group.add_argument("--spider", metavar="SHARE", type=str, help="share to spider")
    spidering_group.add_argument("--spider-folder", metavar="FOLDER", default=".", type=str, help="folder to spider")
    spidering_group.add_argument("--content", action="store_true", help="enable file content searching")
    spidering_group.add_argument("--exclude-dirs", type=str, metavar="DIR_LIST", default="", help="directories to exclude from spidering")
    spidering_group.add_argument("--depth", type=int, help="max spider recursion depth")
    spidering_group.add_argument("--only-files", action="store_true", help="only spider files")
    segroup = spidering_group.add_mutually_exclusive_group()
    segroup.add_argument("--pattern", nargs="+", help="pattern(s) to search for in folders, filenames and file content")
    segroup.add_argument("--regex", nargs="+", help="regex(s) to search for in folders, filenames and file content")

    files_group = smb_parser.add_argument_group("Files", "Options for put and get remote files")
    files_group.add_argument("--put-file", action="append", nargs=2, metavar="FILE", help="Put a local file into remote target, ex: whoami.txt \\\\Windows\\\\Temp\\\\whoami.txt")
    files_group.add_argument("--get-file", action="append", nargs=2, metavar="FILE", help="Get a remote file, ex: \\\\Windows\\\\Temp\\\\whoami.txt whoami.txt")
    files_group.add_argument("--get-folder", action="append", nargs=2, metavar="DIR", help="Get a remote directory, ex: \\\\Windows\\\\Temp\\\\testing testing")
    files_group.add_argument("--recursive", default=False, action="store_true", help="Recursively get a folder")
    files_group.add_argument("--append-host", action="store_true", help="append the host to the get-file filename")

    cmd_exec_group = smb_parser.add_argument_group("Command Execution", "Options for executing commands")
    cmd_exec_group.add_argument("--exec-method", choices={"wmiexec", "mmcexec", "smbexec", "atexec"}, default="wmiexec", help="method to execute the command. Ignored if in MSSQL mode", action=DefaultTrackingAction)
    cmd_exec_group.add_argument("--dcom-timeout", help="DCOM connection timeout", type=int, default=5)
    cmd_exec_group.add_argument("--get-output-tries", help="Number of times atexec/smbexec/mmcexec tries to get results", type=int, default=10)
    cmd_exec_group.add_argument("--codec", default="utf-8", help="Set encoding used (codec) from the target's output. If errors are detected, run chcp.com at the target & map the result with https://docs.python.org/3/library/codecs.html#standard-encodings and then execute again with --codec and the corresponding codec")
    cmd_exec_group.add_argument("--no-output", action="store_true", help="do not retrieve command output")

    cmd_exec_method_group = cmd_exec_group.add_mutually_exclusive_group()
    cmd_exec_method_group.add_argument("-x", metavar="COMMAND", dest="execute", help="execute the specified CMD command")
    cmd_exec_method_group.add_argument("-X", metavar="PS_COMMAND", dest="ps_execute", help="execute the specified PowerShell command")

    posh_group = smb_parser.add_argument_group("Powershell Obfuscation", "Options for PowerShell script obfuscation")
    posh_group.add_argument("--obfs", action="store_true", help="Obfuscate PowerShell scripts")
    posh_group.add_argument("--amsi-bypass", nargs=1, metavar="FILE", help="File with a custom AMSI bypass")
    posh_group.add_argument("--clear-obfscripts", action="store_true", help="Clear all cached obfuscated PowerShell scripts")
    posh_group.add_argument("--force-ps32", action="store_true", help="force PowerShell commands to run in a 32-bit process (may not apply to modules)")
    posh_group.add_argument("--no-encode", action="store_true", default=False, help="Do not encode the PowerShell command ran on target")

    return parser

def get_conditional_action(baseAction):
    class ConditionalAction(baseAction):
        def __init__(self, option_strings, dest, **kwargs):
            x = kwargs.pop("make_required", [])
            super().__init__(option_strings, dest, **kwargs)
            self.make_required = x

        def __call__(self, parser, namespace, values, option_string=None):
            for x in self.make_required:
                x.required = True
            super().__call__(parser, namespace, values, option_string)

    return ConditionalAction
