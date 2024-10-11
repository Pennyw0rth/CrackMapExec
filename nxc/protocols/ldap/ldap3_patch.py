# Ldap3 implementation for NexExec
#
# Authors:
#   LightRadio (@LightxR)
#
# ToDo:
#   [x] Finalize the work ;)
#

import re
import ldap3
import ssl
import socket
from binascii import unhexlify
import random
import tempfile

from pyasn1.codec.ber import encoder, decoder
from pyasn1.error import SubstrateUnderrunError
from pyasn1.type.univ import noValue

from impacket import LOG
from impacket.ldap.ldapasn1 import Filter, Control, SimplePagedResultsControl, ResultCode, Scope, DerefAliases, Operation, \
    KNOWN_CONTROLS, CONTROL_PAGEDRESULTS, NOTIFICATION_DISCONNECT, KNOWN_NOTIFICATIONS, BindRequest, SearchRequest, \
    SearchResultDone, LDAPMessage
from impacket.ntlm import getNTLMSSPType1, getNTLMSSPType3
from impacket.spnego import SPNEGO_NegTokenInit, SPNEGO_NegTokenResp, TypesMech

from typing import Tuple
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    pkcs12,
)
from pyasn1.codec.der import decoder, encoder

__all__ = [
    'LDAPConnection', 'LDAPFilterSyntaxError', 'LDAPFilterInvalidException', 'LDAPSessionError', 'LDAPSearchError',
    'Control', 'SimplePagedResultsControl', 'ResultCode', 'Scope', 'DerefAliases', 'Operation',
    'CONTROL_PAGEDRESULTS', 'KNOWN_CONTROLS', 'NOTIFICATION_DISCONNECT', 'KNOWN_NOTIFICATIONS',
]

# https://tools.ietf.org/search/rfc4515#section-3
DESCRIPTION = r'(?:[a-z][a-z0-9\-]*)'
NUMERIC_OID = r'(?:(?:\d|[1-9]\d+)(?:\.(?:\d|[1-9]\d+))*)'
OID = r'(?:%s|%s)' % (DESCRIPTION, NUMERIC_OID)
OPTIONS = r'(?:(?:;[a-z0-9\-]+)*)'
ATTRIBUTE = r'(%s%s)' % (OID, OPTIONS)
DN = r'(:dn)'
MATCHING_RULE = r'(?::(%s))' % OID

RE_OPERATOR = re.compile(r'([:<>~]?=)')
RE_ATTRIBUTE = re.compile(r'^%s$' % ATTRIBUTE, re.I)
RE_EX_ATTRIBUTE_1 = re.compile(r'^%s%s?%s?$' % (ATTRIBUTE, DN, MATCHING_RULE), re.I)
RE_EX_ATTRIBUTE_2 = re.compile(r'^(){0}%s?%s$' % (DN, MATCHING_RULE), re.I)

# LDAP controls
# https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/3c5e87db-4728-4f29-b164-01dd7d7391ea
LDAP_PAGED_RESULT_OID_STRING = "1.2.840.113556.1.4.319"
# https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/f14f3610-ee22-4d07-8a24-1bf1466cba5f
LDAP_SERVER_NOTIFICATION_OID = "1.2.840.113556.1.4.528"


class LDAPConnection:
    def __init__(self, url, baseDN='', dstIp=None):
        """
        LDAPConnection class

        :param string url:
        :param string baseDN:
        :param string dstIp:

        :return: a LDAP instance, if not raises a LDAPSessionError exception
        """
        self._SSL = False
        self._dstPort = 0
        self._dstHost = 0
        self._socket = None
        self._baseDN = baseDN
        self._dstIp = dstIp

        if url.startswith('ldap://'):
            self._dstPort = 389
            self._SSL = False
            self._dstHost = url[7:]
        elif url.startswith('ldaps://'):
            self._dstPort = 636
            self._SSL = True
            self._dstHost = url[8:]
        elif url.startswith('gc://'):
            self._dstPort = 3268
            self._SSL = False
            self._dstHost = url[5:]
        else:
            raise LDAPSessionError(errorString="Unknown URL prefix: '%s'" % url)

        # Try to connect
        if self._dstIp is not None:
            self.targetHost = self._dstIp
        else:
            self.targetHost = self._dstHost

        if self._SSL is True:
            use_ssl = True
            tls = ldap3.Tls(
                validate=ssl.CERT_NONE,
                version=ssl.PROTOCOL_TLSv1_2,
                ciphers='ALL:@SECLEVEL=0'
            )
        else:
            use_ssl = False
            tls = None
    
        self.ldap_server = ldap3.Server(
            host=self.targetHost,
            port=self._dstPort,
            use_ssl=use_ssl,
            get_info=ldap3.ALL,
            tls=tls            
        )
        self.ldap_connection = ldap3.Connection(server=self.ldap_server)
        self.ldap_connection.bind()


    def kerberosLogin(self, user, password, domain='', lmhash='', nthash='', aesKey='', kdcHost=None, TGT=None,
                      TGS=None, useCache=True):
        """
        logins into the target system explicitly using Kerberos. Hashes are used if RC4_HMAC is supported.

        :param string user: username
        :param string password: password for the user
        :param string domain: domain where the account is valid for (required)
        :param string lmhash: LMHASH used to authenticate using hashes (password is not used)
        :param string nthash: NTHASH used to authenticate using hashes (password is not used)
        :param string aesKey: aes256-cts-hmac-sha1-96 or aes128-cts-hmac-sha1-96 used for Kerberos authentication
        :param string kdcHost: hostname or IP Address for the KDC. If None, the domain will be used (it needs to resolve tho)
        :param struct TGT: If there's a TGT available, send the structure here and it will be used
        :param struct TGS: same for TGS. See smb3.py for the format
        :param bool useCache: whether or not we should use the ccache for credentials lookup. If TGT or TGS are specified this is False

        :return: True, raises a LDAPSessionError if error.
        """

        if lmhash != '' or nthash != '':
            if len(lmhash) % 2:
                lmhash = '0' + lmhash
            if len(nthash) % 2:
                nthash = '0' + nthash
            try:  # just in case they were converted already
                lmhash = unhexlify(lmhash)
                nthash = unhexlify(nthash)
            except TypeError:
                pass

        # Importing down here so pyasn1 is not required if kerberos is not used.
        from impacket.krb5.ccache import CCache
        from impacket.krb5.asn1 import AP_REQ, Authenticator, TGS_REP, seq_set
        from impacket.krb5.kerberosv5 import getKerberosTGT, getKerberosTGS
        from impacket.krb5 import constants
        from impacket.krb5.types import Principal, KerberosTime, Ticket
        import datetime


        if TGT is not None or TGS is not None or aesKey is not None:
            useCache = False

        targetName = 'ldap/%s' % self._dstHost
        if useCache:
            domain, user, TGT, TGS = CCache.parseFile(domain, user, targetName)

        # First of all, we need to get a TGT for the user
        userName = Principal(user, type=constants.PrincipalNameType.NT_PRINCIPAL.value)
        if TGT is None:
            if TGS is None:
                tgt, cipher, oldSessionKey, sessionKey = getKerberosTGT(userName, password, domain, lmhash, nthash,
                                                                        aesKey, kdcHost)
        else:
            tgt = TGT['KDC_REP']
            cipher = TGT['cipher']
            sessionKey = TGT['sessionKey']

        if TGS is None:
            serverName = Principal(targetName, type=constants.PrincipalNameType.NT_SRV_INST.value)
            tgs, cipher, oldSessionKey, sessionKey = getKerberosTGS(serverName, domain, kdcHost, tgt, cipher,
                                                                    sessionKey)
        else:
            tgs = TGS['KDC_REP']
            cipher = TGS['cipher']
            sessionKey = TGS['sessionKey']

            # Let's build a NegTokenInit with a Kerberos REQ_AP

        blob = SPNEGO_NegTokenInit()

        # Kerberos
        blob['MechTypes'] = [TypesMech['MS KRB5 - Microsoft Kerberos 5']]

        # Let's extract the ticket from the TGS
        tgs = decoder.decode(tgs, asn1Spec=TGS_REP())[0]
        ticket = Ticket()
        ticket.from_asn1(tgs['ticket'])

        # Now let's build the AP_REQ
        apReq = AP_REQ()
        apReq['pvno'] = 5
        apReq['msg-type'] = int(constants.ApplicationTagNumbers.AP_REQ.value)

        opts = []
        apReq['ap-options'] = constants.encodeFlags(opts)
        seq_set(apReq, 'ticket', ticket.to_asn1)

        authenticator = Authenticator()
        authenticator['authenticator-vno'] = 5
        authenticator['crealm'] = domain
        seq_set(authenticator, 'cname', userName.components_to_asn1)
        now = datetime.datetime.utcnow()

        authenticator['cusec'] = now.microsecond
        authenticator['ctime'] = KerberosTime.to_asn1(now)

        encodedAuthenticator = encoder.encode(authenticator)

        # Key Usage 11
        # AP-REQ Authenticator (includes application authenticator
        # subkey), encrypted with the application session key
        # (Section 5.5.1)
        encryptedEncodedAuthenticator = cipher.encrypt(sessionKey, 11, encodedAuthenticator, None)

        apReq['authenticator'] = noValue
        apReq['authenticator']['etype'] = cipher.enctype
        apReq['authenticator']['cipher'] = encryptedEncodedAuthenticator

        blob['MechToken'] = encoder.encode(apReq)

        request = ldap3.operation.bind.bind_operation(self.ldap_connection.version, ldap3.SASL, user, None, 'GSS-SPNEGO',
                                                  blob.getData())

        if self.ldap_connection.closed:  # try to open connection if closed
            self.ldap_connection.open(read_server_info=False)

        self.ldap_connection.sasl_in_progress = True
        response = self.ldap_connection.post_send_single_response(self.ldap_connection.send('bindRequest', request, None))
        self.ldap_connection.sasl_in_progress = False
        if response[0]['result'] != 0:
            raise Exception(response)

        self.ldap_connection.bound = True


        return True

    def login(self, user='', password='', domain='', lmhash='', nthash=''):
        """
        logins into the target system

        :param string user: username
        :param string password: password for the user
        :param string domain: domain where the account is valid for
        :param string lmhash: LMHASH used to authenticate using hashes (password is not used)
        :param string nthash: NTHASH used to authenticate using hashes (password is not used)
        :param string authenticationChoice: type of authentication protocol to use (default NTLM)

        :return: True, raises a LDAPSessionError if error.
        """

        ldap_user = f"{domain}\\{user}"

        ldap_connection_kwargs = {'user': ldap_user, 'raise_exceptions': True, 'authentication': ldap3.NTLM}
        if lmhash or nthash:
            lmhash = lmhash if lmhash else "aad3b435b51404eeaad3b435b51404ee"
            nthash = nthash if nthash else "31d6cfe0d16ae931b73c59d7e0c089c0"
            ldap_connection_kwargs['password'] = f"{lmhash}:{nthash}"
        else:
            ldap_connection_kwargs['password'] = password

        self.ldap_connection = ldap3.Connection(self.ldap_server, **ldap_connection_kwargs, auto_bind=True)

        return True

    def schannelLogin(self, user='', domain='', pfx: str=None, key: rsa.RSAPublicKey=None, cert: x509.Certificate=None ):
        """
        logins into the target system

        :param string user: username
        :param string domain: domain where the account is valid for
        :param string pfx : PFX file used to authenticate
        :param string key : KEY file used to authenticate
        :param string cert : CERT file used to authenticate

        :return: True, raises a LDAPSessionError if error.
        """

        if pfx:
            with open(pfx, "rb") as f:
                key, cert = load_pfx(f.read())

            key_file = tempfile.NamedTemporaryFile(delete=False)
            key_file.write(key_to_pem(key))
            key_file.close()

            cert_file = tempfile.NamedTemporaryFile(delete=False)
            cert_file.write(cert_to_pem(cert))
            cert_file.close()        
            
            tls = ldap3.Tls(local_private_key_file=key_file.name, local_certificate_file=cert_file.name, validate=ssl.CERT_NONE)
        else:
            tls = ldap3.Tls(local_private_key_file=key, local_certificate_file=cert, validate=ssl.CERT_NONE)

        ldap_server_kwargs = {'use_ssl': self._SSL,
                              'port': self._dstPort,
                              'get_info': ldap3.ALL,
                              'tls': tls}

        ldapServer = ldap3.Server(self.targetHost, **ldap_server_kwargs)

        ldap_connection_kwargs = dict()
    
        if self._dstPort == 389:
            # StartTLS connection, can bypass channel binding : https://offsec.almond.consulting/bypassing-ldap-channel-binding-with-starttls.html
            ldap_connection_kwargs = {'authentication': ldap3.SASL,
                                      'sasl_mechanism': ldap3.EXTERNAL,
                                      'auto_bind': ldap3.AUTO_BIND_TLS_BEFORE_BIND}

        self.ldap_connection = ldap3.Connection(ldapServer, **ldap_connection_kwargs)

        if self._dstPort == 636:

            self.ldap_connection.open()

        return True


    def search(self, searchBase=None, scope=None, derefAliases=None, sizeLimit=0, timeLimit=0, typesOnly=False,
                 search_filter='(objectClass=*)', attributes=None, searchControls=None, perRecordCallback=None):


        if searchBase is None:
            searchBase = self._baseDN
        if scope is None:
            scope = ldap3.SUBTREE
        if derefAliases is None:
            derefAliases = ldap3.DEREF_NEVER
        if attributes is None:
            attributes = []

        results = []
        try:
            # https://ldap3.readthedocs.io/en/latest/searches.html#the-search-operation
            paged_response = True
            paged_cookie = None
            page_size=1000
            while paged_response == True:
                self.ldap_connection.search(
                    search_base=searchBase,
                    search_filter=search_filter,
                    search_scope=scope,
                    attributes=attributes,
                    size_limit=sizeLimit,
                    paged_size=page_size,
                    paged_cookie=paged_cookie
                )
                if "controls" in self.ldap_connection.result.keys():
                    if LDAP_PAGED_RESULT_OID_STRING in self.ldap_connection.result["controls"].keys():
                        next_cookie = self.ldap_connection.result["controls"][LDAP_PAGED_RESULT_OID_STRING]["value"]["cookie"]
                        if len(next_cookie) == 0:
                            paged_response = False
                        else:
                            paged_response = True
                            paged_cookie = next_cookie
                    else:
                        paged_response = False
                else:
                    paged_response = False
                for entry in self.ldap_connection.response:
                    results.append(entry)
        except ldap3.core.exceptions.LDAPInvalidFilterError as e:
            print("Invalid Filter. (ldap3.core.exceptions.LDAPInvalidFilterError)")
        except ldap3.core.exceptions.LDAPAttributeError as e:
            print("Invalid attribute. (ldap3.core.exceptions.LDAPAttributeError)")
        except Exception as e:
            raise e
        return results


## load_pfx(), key_to_pem() and cert_to_pem() functions from Certipy

def load_pfx(
    pfx: bytes, password: bytes = None
) -> Tuple[rsa.RSAPrivateKey, x509.Certificate, None]:
    return pkcs12.load_key_and_certificates(pfx, password)[:-1]

def key_to_pem(key: rsa.RSAPrivateKey) -> bytes:
    return key.private_bytes(
        Encoding.PEM, PrivateFormat.PKCS8, encryption_algorithm=NoEncryption()
    )

def cert_to_pem(cert: x509.Certificate) -> bytes:
    return cert.public_bytes(Encoding.PEM)




 ## Remaining code from impacket.ldap => to be cleaned/removed

    def _parseFilter(self, filterStr):
        try:
            filterStr = filterStr.decode()
        except AttributeError:
            pass
        filterList = list(reversed(filterStr))
        searchFilter = self._consumeCompositeFilter(filterList)
        if filterList:  # we have not consumed the whole filter string
            raise LDAPFilterSyntaxError("unexpected token: '%s'" % filterList[-1])
        return searchFilter

    def _consumeCompositeFilter(self, filterList):
        try:
            c = filterList.pop()
        except IndexError:
            raise LDAPFilterSyntaxError('EOL while parsing search filter')
        if c != '(':  # filter must start with a '('
            filterList.append(c)
            raise LDAPFilterSyntaxError("unexpected token: '%s'" % c)

        try:
            operator = filterList.pop()
        except IndexError:
            raise LDAPFilterSyntaxError('EOL while parsing search filter')
        if operator not in ['!', '&', '|']:  # must be simple filter in this case
            filterList.extend([operator, c])
            return self._consumeSimpleFilter(filterList)

        filters = []
        while True:
            try:
                filters.append(self._consumeCompositeFilter(filterList))
            except LDAPFilterSyntaxError:
                break

        try:
            c = filterList.pop()
        except IndexError:
            raise LDAPFilterSyntaxError('EOL while parsing search filter')
        if c != ')':  # filter must end with a ')'
            filterList.append(c)
            raise LDAPFilterSyntaxError("unexpected token: '%s'" % c)

        return self._compileCompositeFilter(operator, filters)

    def _consumeSimpleFilter(self, filterList):
        try:
            c = filterList.pop()
        except IndexError:
            raise LDAPFilterSyntaxError('EOL while parsing search filter')
        if c != '(':  # filter must start with a '('
            filterList.append(c)
            raise LDAPFilterSyntaxError("unexpected token: '%s'" % c)

        filter = []
        while True:
            try:
                c = filterList.pop()
            except IndexError:
                raise LDAPFilterSyntaxError('EOL while parsing search filter')
            if c == ')':  # we pop till we find a ')'
                break
            elif c == '(':  # should be no unencoded parenthesis
                filterList.append(c)
                raise LDAPFilterSyntaxError("unexpected token: '('")
            else:
                filter.append(c)

        filterStr = ''.join(filter)
        try:
            # https://tools.ietf.org/search/rfc4515#section-3
            attribute, operator, value = RE_OPERATOR.split(filterStr, 1)
        except ValueError:
            raise LDAPFilterInvalidException("invalid filter: '(%s)'" % filterStr)

        return self._compileSimpleFilter(attribute, operator, value)

    @staticmethod
    def _compileCompositeFilter(operator, filters):
        searchFilter = Filter()
        if operator == '!':
            if len(filters) != 1:
                raise LDAPFilterInvalidException("'not' filter must have exactly one element")
            searchFilter['not'].setComponents(*filters)
        elif operator == '&':
            if len(filters) == 0:
                raise LDAPFilterInvalidException("'and' filter must have at least one element")
            searchFilter['and'].setComponents(*filters)
        elif operator == '|':
            if len(filters) == 0:
                raise LDAPFilterInvalidException("'or' filter must have at least one element")
            searchFilter['or'].setComponents(*filters)

        return searchFilter

    @staticmethod
    def _compileSimpleFilter(attribute, operator, value):
        searchFilter = Filter()
        if operator == ':=':  # extensibleMatch
            match = RE_EX_ATTRIBUTE_1.match(attribute) or RE_EX_ATTRIBUTE_2.match(attribute)
            if not match:
                raise LDAPFilterInvalidException("invalid filter attribute: '%s'" % attribute)
            attribute, dn, matchingRule = match.groups()
            if attribute:
                searchFilter['extensibleMatch']['type'] = attribute
            if dn:
                searchFilter['extensibleMatch']['dnAttributes'] = bool(dn)
            if matchingRule:
                searchFilter['extensibleMatch']['matchingRule'] = matchingRule
            searchFilter['extensibleMatch']['matchValue'] = LDAPConnection._processLdapString(value)
        else:
            if not RE_ATTRIBUTE.match(attribute):
                raise LDAPFilterInvalidException("invalid filter attribute: '%s'" % attribute)
            if value == '*' and operator == '=':  # present
                searchFilter['present'] = attribute
            elif '*' in value and operator == '=':  # substring
                assertions = [LDAPConnection._processLdapString(assertion) for assertion in value.split('*')]
                choice = searchFilter['substrings']['substrings'].getComponentType()
                substrings = []
                if assertions[0]:
                    substrings.append(choice.clone().setComponentByName('initial', assertions[0]))
                for assertion in assertions[1:-1]:
                    substrings.append(choice.clone().setComponentByName('any', assertion))
                if assertions[-1]:
                    substrings.append(choice.clone().setComponentByName('final', assertions[-1]))
                searchFilter['substrings']['type'] = attribute
                searchFilter['substrings']['substrings'].setComponents(*substrings)
            elif '*' not in value:  # simple
                value = LDAPConnection._processLdapString(value)
                if operator == '=':
                    searchFilter['equalityMatch'].setComponents(attribute, value)
                elif operator == '~=':
                    searchFilter['approxMatch'].setComponents(attribute, value)
                elif operator == '>=':
                    searchFilter['greaterOrEqual'].setComponents(attribute, value)
                elif operator == '<=':
                    searchFilter['lessOrEqual'].setComponents(attribute, value)
            else:
                raise LDAPFilterInvalidException("invalid filter '(%s%s%s)'" % (attribute, operator, value))

        return searchFilter


    @classmethod
    def _processLdapString(cls, ldapstr):
        def replace_escaped_chars(match):
            return chr(int(match.group(1), 16))  # group(1) == "XX" (valid hex)

        escaped_chars = re.compile(r'\\([0-9a-fA-F]{2})')  # Capture any sequence of "\XX" (where XX is a valid hex)
        return re.sub(escaped_chars, replace_escaped_chars, ldapstr)


class LDAPFilterSyntaxError(SyntaxError):
    pass


class LDAPFilterInvalidException(Exception):
    pass


class LDAPSessionError(Exception):
    """
    This is the exception every client should catch
    """

    def __init__(self, error=0, packet=0, errorString=''):
        Exception.__init__(self)
        self.error = error
        self.packet = packet
        self.errorString = errorString

    def getErrorCode(self):
        return self.error

    def getErrorPacket(self):
        return self.packet

    def getErrorString(self):
        return self.errorString

    def __str__(self):
        return self.errorString


class LDAPSearchError(LDAPSessionError):
    def __init__(self, error=0, packet=0, errorString='', answers=None):
        LDAPSessionError.__init__(self, error, packet, errorString)
        if answers is None:
            answers = []
        self.answers = answers

    def getAnswers(self):
        return self.answers
