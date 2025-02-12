from impacket.ldap import ldapasn1 as ldapasn1_impacket

class NXCModule:
    """Module by @Marshall-Hallenbeck
    Retrieves Group Policy Objects (GPOs) in Active Directory
    """
    
    name = "get_gpos"
    description = "Retrieves Group Policy Objects (GPOs) in Active Directory"
    supported_protocols = ["ldap"]
    opsec_safe = True
    multiple_hosts = False
    
    def __init__(self):
        self.context = None
        self.module_options = None
        self.gpo_name = None
        self.fuzzy_search = False
        self.all_props = False

    def options(self, context, module_options):
        """
        NAME        Name of the GPO (default retrieve all GPOs)
        FUZZY       Fuzzy search for name of GPOs (using wildcards)
        ALL_PROPS   Retrieve all properties of the GPO (default is name, guid, and sysfile path)
        """
        self.gpo_name = module_options.get("NAME")
        self.fuzzy_search = module_options.get("FUZZY")
        self.all_props = module_options.get("ALL_PROPS")

    def on_login(self, context, connection):
        # name is actually the GUID of the GPO
        attributes = ["*"] if self.all_props else ["displayName", "name", "gPCFileSysPath"]
        
        if self.gpo_name:
            context.log.display(f"Searching for GPO '{self.gpo_name}'")
            self.gpo_name = f"*{self.gpo_name}*" if self.fuzzy_search else self.gpo_name
            search_filter = f"(&(objectCategory=groupPolicyContainer)(displayname={self.gpo_name}))"
        else:        
            context.log.display("Searching for all GPOs")
            search_filter = "(objectCategory=groupPolicyContainer)"
        context.log.debug(f"Search filter: '{search_filter}'")

        results = connection.search(search_filter, attributes, 10000)
        results = [r for r in results if isinstance(r, ldapasn1_impacket.SearchResultEntry)]
        context.log.success(f"GPOs Found: {len(results)}")
        
        if results:
            for gpo in results:
                gpo_values = {str(attr["type"]).lower(): str(attr["vals"][0]) for attr in gpo["attributes"]}
                context.log.success(f"GPO Found: '{gpo_values['displayname']}'")
                for k, v in gpo_values.items():
                    if self.gpo_name:
                        if k == "displayname":
                            context.log.highlight(f"Display Name: {v}")
                        elif k == "name":
                            context.log.highlight(f"GUID: {v}")
                        else:
                            context.log.highlight(f"{k}: {v}")
                    else:
                        context.log.highlight(f"{k}: {v}")
        else:
            if self.gpo_name:
                context.log.error(f"No GPO found with the name '{self.gpo_name}'")
            else:
                context.log.error("No GPOs found")