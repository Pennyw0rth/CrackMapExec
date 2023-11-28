def proto_args(parser, parents):
    xfreerdp_parser = parser.add_parser("xfreerdp", help="own stuff using RDP (xfreerdp)", parents=parents)
    xfreerdp_parser.add_argument("-H", "--hash", metavar="HASH", dest="hash", nargs="+", default=[], help="NTLM hash(es) or file(s) containing NTLM hashes")
    xfreerdp_parser.add_argument("--port", type=int, default=3389, help="Custom RDP port")
    xfreerdp_parser.add_argument("--rdp-timeout", type=int, default=5, help="RDP timeout on socket connection, defalut is %(default)ss")

    dgroup = xfreerdp_parser.add_mutually_exclusive_group()
    dgroup.add_argument("-d", metavar="DOMAIN", dest="domain", type=str, default=None, help="domain to authenticate to")
    dgroup.add_argument("--local-auth", action="store_true", help="authenticate locally to each target")
    return parser