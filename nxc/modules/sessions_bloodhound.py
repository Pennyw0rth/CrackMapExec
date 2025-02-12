from pywerview.cli.helpers import get_netloggedon

class NXCModule:
    name = "sessions_bloodhound"
    description = "Collects logged on users and add it on bloodhound"
    supported_protocols = ["smb"]
    opsec_safe = True 
    multiple_hosts = True

    def options(self, context, module_options):
        # Define options if needed
        pass
    def on_admin_login(self, context, connection):
        hostname = connection.hostname+"$"
        host = connection.host
        domain = connection.domain
        username = connection.username
        password = getattr(connection, "password", "")
        lmhash = getattr(connection, "lmhash", "")
        nthash = getattr(connection, "nthash", "")
        config = connection.config
        logged_on = []
        try:
            logged_on = get_netloggedon(
                host,
                domain,
                username,
                password,
                lmhash=lmhash,
                nthash=nthash,
            )
            logged_on = {f"{user.wkui1_username}" for user in logged_on if not user.wkui1_username.endswith("$")}

            context.log.debug("Enumerated logged_on users")
            for user in logged_on:
                context.log.debug(user)
        except Exception as e:
            context.log.fail(f"Error enumerating logged on users: {e}")

        if config.get("BloodHound", "bh_enabled") != "False":
        # we do a conditional import here to avoid loading these if BH isn't enabled
            from neo4j import GraphDatabase
            from neo4j.exceptions import AuthError, ServiceUnavailable

            uri = f"bolt://{config.get('BloodHound', 'bh_uri')}:{config.get('BloodHound', 'bh_port')}"

            driver = GraphDatabase.driver(
                uri,
                auth=(
                    config.get("BloodHound", "bh_user"),
                    config.get("BloodHound", "bh_pass"),
                ),
                encrypted=False,
            )
            try:
                with driver.session().begin_transaction() as tx:
                    for user in logged_on:
                        data = tx.run(f"""MATCH (c:Computer {{samaccountname:\"{hostname}\"}}) 
                                          MATCH (u:User {{samaccountname:\"{user}\"}})
                                          MERGE (c)-[r:HasSession {{nxc: true}}]->(u)""").data()
                        context.log.highlight(f"Relation HasSession add between {user} and {hostname} ")
            except AuthError:
                context.log.fail(f"Provided Neo4J credentials ({config.get('BloodHound', 'bh_user')}:{config.get('BloodHound', 'bh_pass')}) are not valid.")
            except ServiceUnavailable:
                context.log.fail(f"Neo4J does not seem to be available on {uri}.")
            except Exception as e:
                context.log.fail(f"Unexpected error with Neo4J: {e}")
            finally:
                driver.close()
        else:
            context.logger.fail("Bloodhound is not enable in the configuration see https://www.netexec.wiki/getting-started/bloodhound-integration for more information")
