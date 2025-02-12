from nxc.helpers.modules import add_loot_data
class NXCModule:
    """
    Example:
    -------
    Module by @yomama
    """

    name = "example_module"  # Make sure this is unique and one word (no spaces)
    description = "I do something"
    supported_protocols = []  # Example: ['smb', 'mssql']
    opsec_safe = True  # Does the module touch disk?
    multiple_hosts = True  # Does it make sense to run this module on multiple hosts at a time?

    def __init__(self):
        self.context = None
        self.module_options = None

    def options(self, context, module_options):
        """Required.
        Module options get parsed here. Additionally, put the modules usage here as well
        """

    def on_login(self, context, connection):
        """Concurrent.
        Required if on_admin_login is not present. This gets called on each authenticated connection
        """
        # Logging best practice
        # Mostly you should use these functions to display information to the user
        context.log.display("I'm doing something")  # Use this for every normal message ([*] I'm doing something)
        context.log.success("I'm doing something")  # Use this for when something succeeds ([+] I'm doing something)
        context.log.fail("I'm doing something")  # Use this for when something fails ([-] I'm doing something), for example a remote registry entry is missing which is needed to proceed
        context.log.highlight("I'm doing something")  # Use this for when something is important and should be highlighted, printing credentials for example

        # These are for debugging purposes
        context.log.info("I'm doing something")  # This will only be displayed if the user has specified the --verbose flag, so add additional info that might be useful
        context.log.debug("I'm doing something")  # This will only be displayed if the user has specified the --debug flag, so add info that you would might need for debugging errors

        # These are for more critical error handling
        context.log.error("I'm doing something")  # This will not be printed in the module context and should only be used for critical errors (e.g. a required python file is missing)
        try:
            raise Exception("Exception that might have occurred")
        except Exception as e:
            context.log.exception(f"Exception occurred: {e}")  # This will display an exception traceback screen after an exception was raised and should only be used for critical errors
            
        # Use this function to add loot data you want to save to $NXC_PATH/loot/$MODULE_NAME/$FILENAME
        add_loot_data(self.name, "custom_loot_file.txt", "Data can be anything you want, passwords, hashes, or anything")

    def on_admin_login(self, context, connection):
        """Concurrent.
        Required if on_login is not present
        This gets called on each authenticated connection with Administrative privileges
        """
        # Use this function to add loot data you want to save to $NXC_PATH/loot/$MODULE_NAME/$FILENAME
        add_loot_data(self.name, "custom_loot_file.txt", "Data can be anything you want, passwords, hashes, or anything")

    def on_request(self, context, request):
        """Optional.
        If the payload needs to retrieve additional files, add this function to the module
        """

    def on_response(self, context, response):
        """Optional.
        If the payload sends back its output to our server, add this function to the module to handle its output
        """

    def on_shutdown(self, context, connection):
        """Optional.
        Do something on shutdown
        """
