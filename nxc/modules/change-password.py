import sys
from impacket.dcerpc.v5 import samr, epm, transport
from impacket.dcerpc.v5.rpcrt import DCERPCException

class NXCModule:
    """
    Module for changing or resetting user passwords
    Module by Fagan Afandiyev and termanix
    """

    name = "change-password"
    description = "Change or reset user passwords via various protocols"
    supported_protocols = ["smb"]
    opsec_safe = True
    multiple_hosts = False

    def options(self, context, module_options):
        """
        Module options for password change

        Required options:
        If STATUS_PASSWORD_MUST_CHANGE or STATUS_PASSWORD_EXPIRED (Change password for current user)
            netexec smb <DC_IP> -u username -p oldpass -M change-password -o OLDPASS='oldpass' NEWPASS='newpass'
            netexec smb <DC_IP> -u username -H oldnthash -M change-password -o OLDNTHASH='oldnthash' NEWPASS='newpass'
        
        If want to change other user's password (with forcechangepassword priv or admin rights)
            netexec smb <DC_IP> -u username -p password -M change-password -o USER='target_user' NEWPASS='target_user_newpass'
            netexec smb <DC_IP> -u username -p password -M change-password -o USER='target_user' NEWNTHASH='target_user_newnthash'
        
        NEWPASS or NEWHASH
        """
        self.context = context
        self.newpass = module_options.get("NEWPASS")
        self.newhash = module_options.get("NEWNTHASH")
        self.oldpass = module_options.get("OLDPASS")
        self.oldhash = module_options.get("OLDNTHASH")
        self.target_user = module_options.get("USER")
        self.reset = module_options.get("RESET", True)

        if not self.newpass and not self.newhash:
            context.log.fail("Either NEWPASS or NEWNTHASH is required!")
            sys.exit(1)

    def authenticate(self, context, connection, protocol, anonymous=False):
        # Authenticate to the target using DCE/RPC with either user credentials or a null session. Establishes a connection and binds to the SAMR service.
        try:
            # Map to the SAMR endpoint on the target
            string_binding = epm.hept_map(connection.host, samr.MSRPC_UUID_SAMR, protocol=protocol)
            rpctransport = transport.DCERPCTransportFactory(string_binding)
            rpctransport.setRemoteHost(connection.host)

            if anonymous:
                rpctransport.set_credentials("", "", "", "", "", "")
                rpctransport.set_kerberos(False, None)
                context.log.info("Connecting with null session credentials.")
            else:
                rpctransport.set_credentials(
                    connection.username,
                    connection.password,
                    connection.domain,
                    connection.lmhash,
                    connection.nthash,
                    aesKey=connection.aesKey,
                )
                context.log.info(f"Connecting as {connection.domain}\\{connection.username}")

            # Connect to the DCE/RPC endpoint and bind to the SAMR service
            dce = rpctransport.get_dce_rpc()
            dce.connect()
            context.log.info("[+] Successfully connected to DCE/RPC")
            dce.bind(samr.MSRPC_UUID_SAMR)
            context.log.info("[+] Successfully bound to SAMR")
            return dce

        except DCERPCException as e:
            context.log.fail(f"DCE/RPC Exception: {e!s}")
            raise

    def on_login(self, context, connection):
        target_username = self.target_user or connection.username
        target_domain = connection.domain
        
        # If OLDPASS or OLDHASH are not specified, default to the credentials used for authentication.

        if not self.oldpass:
            self.oldpass = connection.password
        if not self.oldhash:
            self.oldhash = connection.nthash
        
        
        new_lmhash, new_nthash = "", ""

        # Parse new hash values if provided
        if self.newhash:
            try:
                new_lmhash, new_nthash = self.newhash.split(":")
            except ValueError:
                new_nthash = self.newhash

        try:
            self.anonymous = False
            self.dce = self.authenticate(context, connection, protocol="ncacn_np", anonymous=self.anonymous)
        except Exception as e:
            # Handle specific errors like password expiration or must be change
            if "STATUS_PASSWORD_MUST_CHANGE" in str(e) or "STATUS_PASSWORD_EXPIRED" in str(e):
                context.log.warning("Password must be changed. Trying with null session.")
                self.anonymous = True
                self.dce = self.authenticate(context, connection, protocol="ncacn_ip_tcp", anonymous=self.anonymous)
            elif "STATUS_LOGON_FAILURE" in str(e):
                context.log.critical("Authentication failure: wrong credentials.")
                return False
            else:
                raise

        try:
            # Perform the SMB SAMR password change
            self._smb_samr_change(context, connection, target_username, target_domain, self.oldhash, self.newpass, new_nthash)
        except Exception as e:
            context.log.fail(f"Password change failed: {e}")

    def _smb_samr_change(self, context, connection, target_username, target_domain, oldHash, newPassword, newHash):
        try:
            if not self.anonymous:
                # Connect to the target server and retrieve handles
                server_handle = samr.hSamrConnect(self.dce, connection.host + "\x00")["ServerHandle"]  # Does not work for null session auth.
                domain_sid = samr.hSamrLookupDomainInSamServer(self.dce, server_handle, target_domain)["DomainId"]
                domain_handle = samr.hSamrOpenDomain(self.dce, server_handle, domainId=domain_sid)["DomainHandle"]
                user_rid = samr.hSamrLookupNamesInDomain(self.dce, domain_handle, (target_username,))["RelativeIds"]["Element"][0]
                user_handle = samr.hSamrOpenUser(self.dce, domain_handle, userId=user_rid)["UserHandle"]

                if self.reset:
                    # Change the password with new password hash
                    samr.hSamrSetNTInternal1(self.dce, user_handle, newPassword, newHash)
                    context.log.success(f"Successfully changed password for {target_username}")
                else:
                    # Change the password with new password
                    samr.hSamrUnicodeChangePasswordUser2(
                        self.dce, "\x00", target_username, self.oldpass, newPassword, "", ""
                    )
                    context.log.success(f"Successfully changed password for {target_username}")
            else:
                # Handle anonymous/null session password change
                self.mustchangePassword(target_username, target_domain, self.oldpass, newPassword, "", oldHash, "", newHash)
        except AttributeError:
            context.log.fail("SMB-SAMR password change failed: Ensure that either the OLDPASS or OLDNTHASH option is provided and attempt again.")
        except Exception as e:
            context.log.fail(f"SMB-SAMR password change failed: {e}")
        finally:
            self.dce.disconnect()

    def mustchangePassword(self, target_username, targetDomain, oldPassword, newPassword, oldPwdHashLM, oldPwdHashNT, newPwdHashLM, newPwdHashNT):
        if newPassword and oldPassword:
            # Change password using old and new plaintext passwords
            samr.hSamrUnicodeChangePasswordUser2(self.dce, "\x00", target_username, oldPassword, newPassword, "", "")
            self.context.log.success(f"Successfully changed password for {target_username}")
        elif newPassword and oldPwdHashNT: 
            # Change password using hash for authentication
            samr.hSamrUnicodeChangePasswordUser2(self.dce, "\x00", target_username, oldPassword, newPassword, "", oldPwdHashNT)
            self.context.log.success(f"Successfully changed password for {target_username}")
        else:
            # Use NT internal function to set new password or hash
            samr.hSamrSetNTInternal1(self.dce, target_username, newPassword, newPwdHashNT)
            self.context.log.success(f"Successfully changed password for {target_username}")
