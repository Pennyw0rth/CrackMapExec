from nxc.helpers.args import DisplayDefaultsNotNone


def proto_args(parser, parents):
    winrm_parser = parser.add_parser("winrm", help="own stuff using WINRM", parents=parents, formatter_class=DisplayDefaultsNotNone)
    winrm_parser.add_argument("-H", "--hash", metavar="HASH", dest="hash", nargs="+", default=[], help="NTLM hash(es) or file(s) containing NTLM hashes")
    winrm_parser.add_argument("--port", nargs="+", default=["5985", "5986"], help="WinRM port - format: 'http-port https-port'(with space separated) or 'single-port' (http & https will use same port when given single port)")
    winrm_parser.add_argument("--check-proto", nargs="+", default=["http", "https"], help="Choose what prorocol you want to check - format: 'http https'(with space separated) or 'single-protocol'")
    winrm_parser.add_argument("--laps", dest="laps", metavar="LAPS", type=str, help="LAPS authentification", nargs="?", const="administrator")
    winrm_parser.add_argument("--http-timeout", dest="http_timeout", type=int, default=10, help="HTTP timeout for WinRM connections")

    dgroup = winrm_parser.add_mutually_exclusive_group()
    dgroup.add_argument("-d", metavar="DOMAIN", dest="domain", type=str, default=None, help="domain to authenticate to")
    dgroup.add_argument("--local-auth", action="store_true", help="authenticate locally to each target")

    cgroup = winrm_parser.add_argument_group("Credential Gathering", "Options for gathering credentials")
    cgroup.add_argument("--dump-method", action="store", default="cmd", choices={"cmd", "powershell"}, help="Select shell type in hashes dump")
    cgroup.add_argument("--sam", action="store_true", help="dump SAM hashes from target systems")
    cgroup.add_argument("--lsa", action="store_true", help="dump LSA secrets from target systems")

    cgroup = winrm_parser.add_argument_group("Command Execution", "Options for executing commands")
    cgroup.add_argument("--codec", default="utf-8", help="Set encoding used (codec) from the target's output. If errors are detected, run chcp.com at the target & map the result with https://docs.python.org/3/library/codecs.html#standard-encodings and then execute again with --codec and the corresponding codec")
    cgroup.add_argument("--no-output", action="store_true", help="do not retrieve command output")
    cgroup.add_argument("-x", metavar="COMMAND", dest="execute", help="execute the specified command")
    cgroup.add_argument("-X", metavar="PS_COMMAND", dest="ps_execute", help="execute the specified PowerShell command")

    return parser