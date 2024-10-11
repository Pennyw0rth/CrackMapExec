import argparse
import argcomplete
import sys
from argparse import RawTextHelpFormatter
from os import listdir
from os.path import dirname
from os.path import join as path_join
import nxc
from nxc.paths import NXC_PATH
from nxc.loaders.protocolloader import ProtocolLoader
from nxc.helpers.logger import highlight
from nxc.helpers.args import DisplayDefaultsNotNone
from nxc.logger import nxc_logger, setup_debug_logging
import importlib.metadata


def gen_cli_args():
    setup_debug_logging()
    
    try:
        VERSION, COMMIT = importlib.metadata.version("netexec").split("+")
    except ValueError:
        VERSION = importlib.metadata.version("netexec")
        COMMIT = ""
    CODENAME = "ItsAlwaysDNS"
    nxc_logger.debug(f"NXC VERSION: {VERSION} - {CODENAME} - {COMMIT}")
    
    generic_parser = argparse.ArgumentParser(add_help=False, formatter_class=DisplayDefaultsNotNone)
    generic_group = generic_parser.add_argument_group("Generic", "Generic options for nxc across protocols")
    generic_group.add_argument("--version", action="store_true", help="Display nxc version")
    generic_group.add_argument("-t", "--threads", type=int, dest="threads", default=256, help="set how many concurrent threads to use")
    generic_group.add_argument("--timeout", default=None, type=int, help="max timeout in seconds of each thread")
    generic_group.add_argument("--jitter", metavar="INTERVAL", type=str, help="sets a random delay between each authentication")
    
    output_parser = argparse.ArgumentParser(add_help=False, formatter_class=DisplayDefaultsNotNone)
    output_group = output_parser.add_argument_group("Output", "Options to set verbosity levels and control output")
    output_group.add_argument("--verbose", action="store_true", help="enable verbose output")
    output_group.add_argument("--debug", action="store_true", help="enable debug level information")
    output_group.add_argument("--no-progress", action="store_true", help="do not displaying progress bar during scan")
    output_group.add_argument("--log", metavar="LOG", help="export result into a custom file")
    
    dns_parser = argparse.ArgumentParser(add_help=False, formatter_class=DisplayDefaultsNotNone)
    dns_group = dns_parser.add_argument_group("DNS")
    dns_group.add_argument("-6", dest="force_ipv6", action="store_true", help="Enable force IPv6")
    dns_group.add_argument("--dns-server", action="store", help="Specify DNS server (default: Use hosts file & System DNS)")
    dns_group.add_argument("--dns-tcp", action="store_true", help="Use TCP instead of UDP for DNS queries")
    dns_group.add_argument("--dns-timeout", action="store", type=int, default=3, help="DNS query timeout in seconds")
    
    parser = argparse.ArgumentParser(
        description=rf"""
     .   .
    .|   |.     _   _          _     _____
    ||   ||    | \ | |   ___  | |_  | ____| __  __   ___    ___
    \\( )//    |  \| |  / _ \ | __| |  _|   \ \/ /  / _ \  / __|
    .=[ ]=.    | |\  | |  __/ | |_  | |___   >  <  |  __/ | (__
   / /ॱ-ॱ\ \   |_| \_|  \___|  \__| |_____| /_/\_\  \___|  \___|
   ॱ \   / ॱ
     ॱ   ॱ

    The network execution tool
    Maintained as an open source project by @NeffIsBack, @MJHallenbeck, @_zblurx
    
    For documentation and usage examples, visit: https://www.netexec.wiki/

    {highlight('Version', 'red')} : {highlight(VERSION)}
    {highlight('Codename', 'red')}: {highlight(CODENAME)}
    {highlight('Commit', 'red')}  : {highlight(COMMIT)}
    """,
        formatter_class=RawTextHelpFormatter,
        parents=[generic_parser, output_parser, dns_parser]
    )

    # we do module arg parsing here so we can reference the module_list attribute below
    module_parser = argparse.ArgumentParser(add_help=False, formatter_class=DisplayDefaultsNotNone)
    mgroup = module_parser.add_argument_group("Modules", "Options for nxc modules")
    mgroup.add_argument("-M", "--module", choices=get_module_names(), action="append", metavar="MODULE", help="module to use")
    mgroup.add_argument("-o", metavar="MODULE_OPTION", nargs="+", default=[], dest="module_options", help="module options")
    mgroup.add_argument("-L", "--list-modules", action="store_true", help="list available modules")
    mgroup.add_argument("--options", dest="show_module_options", action="store_true", help="display module options")

    subparsers = parser.add_subparsers(title="Available Protocols", dest="protocol")

    std_parser = argparse.ArgumentParser(add_help=False, parents=[generic_parser, output_parser, dns_parser], formatter_class=DisplayDefaultsNotNone)
    std_parser.add_argument("target", nargs="+" if not (module_parser.parse_known_args()[0].list_modules or module_parser.parse_known_args()[0].show_module_options or generic_parser.parse_known_args()[0].version) else "*", type=str, help="the target IP(s), range(s), CIDR(s), hostname(s), FQDN(s), file(s) containing a list of targets, NMap XML or .Nessus file(s)")
    credential_group = std_parser.add_argument_group("Authentication", "Options for authenticating")
    credential_group.add_argument("-u", "--username", metavar="USERNAME", dest="username", nargs="+", default=[], help="username(s) or file(s) containing usernames")
    credential_group.add_argument("-p", "--password", metavar="PASSWORD", dest="password", nargs="+", default=[], help="password(s) or file(s) containing passwords")
    credential_group.add_argument("-id", metavar="CRED_ID", nargs="+", default=[], type=str, dest="cred_id", help="database credential ID(s) to use for authentication")
    credential_group.add_argument("--ignore-pw-decoding", action="store_true", help="Ignore non UTF-8 characters when decoding the password file")
    credential_group.add_argument("--no-bruteforce", action="store_true", help="No spray when using file for username and password (user1 => password1, user2 => password2)")
    credential_group.add_argument("--continue-on-success", action="store_true", help="continues authentication attempts even after successes")
    credential_group.add_argument("--gfail-limit", metavar="LIMIT", type=int, help="max number of global failed login attempts")
    credential_group.add_argument("--ufail-limit", metavar="LIMIT", type=int, help="max number of failed login attempts per username")
    credential_group.add_argument("--fail-limit", metavar="LIMIT", type=int, help="max number of failed login attempts per host")

    kerberos_group = std_parser.add_argument_group("Kerberos", "Options for Kerberos authentication")
    kerberos_group.add_argument("-k", "--kerberos", action="store_true", help="Use Kerberos authentication")
    kerberos_group.add_argument("--use-kcache", action="store_true", help="Use Kerberos authentication from ccache file (KRB5CCNAME)")
    kerberos_group.add_argument("--aesKey", metavar="AESKEY", nargs="+", help="AES key to use for Kerberos Authentication (128 or 256 bits)")
    kerberos_group.add_argument("--kdcHost", metavar="KDCHOST", help="FQDN of the domain controller. If omitted it will use the domain part (FQDN) specified in the target parameter")

    certificate_group = std_parser.add_argument_group("Certificate", "Options for Certificate authentication")
    certificate_group.add_argument("-pfx", metavar="PFX", action="store", default=None, dest="pfx", help=".pfx file for certificate authentication")
    certificate_group.add_argument("-key", metavar="KEY", action="store", default=None, dest="key", help=".key file for certificate authentication")
    certificate_group.add_argument("-cert", metavar="CERT", action="store", default=None, dest="cert", help=".crt file fertificate authentication")

    server_group = std_parser.add_argument_group("Servers", "Options for nxc servers")
    server_group.add_argument("--server", choices={"http", "https"}, default="https", help="use the selected server")
    server_group.add_argument("--server-host", type=str, default="0.0.0.0", metavar="HOST", help="IP to bind the server to")
    server_group.add_argument("--server-port", metavar="PORT", type=int, help="start the server on the specified port")
    server_group.add_argument("--connectback-host", type=str, metavar="CHOST", help="IP for the remote system to connect back to")    

    p_loader = ProtocolLoader()
    protocols = p_loader.get_protocols()

    try:
        for protocol in protocols:
            protocol_object = p_loader.load_protocol(protocols[protocol]["argspath"])
            subparsers = protocol_object.proto_args(subparsers, [std_parser, module_parser])
    except Exception as e:
        nxc_logger.exception(f"Error loading proto_args from proto_args.py file in protocol folder: {protocol} - {e}")

    argcomplete.autocomplete(parser)
    args = parser.parse_args()

    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)

    if args.version:
        print(f"{VERSION} - {CODENAME} - {COMMIT}")
        sys.exit(1)

    # Multiply output_tries by 10 to enable more fine granural control, see exec methods
    if hasattr(args, "get_output_tries"):
        args.get_output_tries = args.get_output_tries * 10

    return args


def get_module_names():
    """Get module names without initializing them"""
    modules = []
    modules_paths = [
        path_join(dirname(nxc.__file__), "modules"),
        path_join(NXC_PATH, "modules"),
    ]

    for path in modules_paths:
        modules.extend([module[:-3] for module in listdir(path) if module[-3:] == ".py" and module != "example_module.py"])
    return sorted(modules, key=str.casefold)
