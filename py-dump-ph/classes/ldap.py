import ldap3
import ssl
import re
import ast
import pprint
import collections
from ldap3.protocol.rfc2849 import search_response_to_ldif
from string import ascii_lowercase, digits

PARTLEN = 2

class LdapErrorException(Exception):
    def __init__(self, message=None, errors=None):
        super(LdapErrorException, self).__init__(message)
        self.errors = errors

class TestFailedException(Exception):
    def __init__(self, message=None, errors=None):
        super(TestFailedException, self).__init__(message)
        self.errors = errors

class TargetUser(object):
    def __init__(self,entry):
        self.entry = entry

    def dn(self):
        return str(self.entry.distinguishedName)


class Ldap(object):
    def __init__(self,config):
        self.config = config

    def run_dump(self):
        self._test_connect()
        self._test_naming_contexts()
        self._test_search()
        return

    def _dump_user_data(self):
        ordered_dict = collections.OrderedDict(self.target_user.__dict__)
        pp = pprint.PrettyPrinter(indent=4)
        pp.pprint(ordered_dict)
        return


    def _test_search(self):
        count = 0
        dn = self.config.dump_config.test_target_base_dn
        f = self.config.dump_config.test_target_filter
        all_entries = list()

        output_file = open(self.config.cmdline_args.output, 'w')
        output_file.close()

        written_entries = 0
        try:

            letters = ascii_lowercase + digits + " " + "äöüß"

            for c1 in letters :
                print("now : {}* seen: {} records".format(c1,count))
                for c2 in letters:
                    for c3 in letters:
                        for c4 in letters:
                            partkey = "{}{}{}{}".format(c1,c2,c3,c4)
                            filter = "(&{}(cn={}*))".format(f, partkey)
                            #print(filter)
                            result = self.connection.search(
                                search_base=dn,
                                search_filter=filter,
                                dereference_aliases=ldap3.DEREF_NEVER,
                                search_scope=ldap3.SUBTREE,
                                attributes=['*']
                            )
                            cr = self.connection.result
                            if (cr['result'] != 0):
                                print ("WARNING: {} on {}".format(cr['description'],filter))

                            for entry in self.connection.entries:
                                edict = {
                                    'dn': entry.entry_dn,
                                    'raw_attributes': entry.entry_raw_attributes,
                                }
                                all_entries.append(edict)
                                count +=1

                        if count > written_entries:
                            ldif = search_response_to_ldif(all_entries, all_base64=False, sort_order=None)
                            ldif.pop()
                            output_file = open(self.config.cmdline_args.output, 'a')
                            for l in ldif:
                                output_file.write(l + "\n")
                            output_file.close()
                            all_entries = list()
                            written_entries = count

                #ldif = entry.entry_to_ldif(stream=output_file)

        except (ldap3.core.exceptions.LDAPInvalidFilterError,
                ldap3.core.exceptions.LDAPObjectClassError) as e:
            raise LdapErrorException(e)

    def _test_connect(self):

        try:
            if self.config.dump_config.cacertfile or self.config.dump_config.cacertpath:
                if self.config.dump_config.verifyssl:
                    validate = ssl.CERT_REQUIRED
                else:
                    validate = ssl.CERT_NONE
                tls = ldap3.Tls(
                    validate=validate,
                    ca_certs_file=self.config.dump_config.cacertfile,
                    ca_certs_path=self.config.dump_config.cacertpath,
                    valid_names=self.config.dump_config.alt_names
                )
            else:
                tls = ldap3.Tls(validate=ssl.CERT_NONE)
        except ldap3.core.exceptions.LDAPSSLConfigurationError as e:
            raise LdapErrorException(e)

        self.server = ldap3.Server(
            host=self.config.dump_config.host,
            port=636,
            use_ssl=True,
            tls=tls,
            get_info=ldap3.ALL)
        try:
            self.connection = ldap3.Connection(
                self.server,
                self.config.dump_config.admin_user,
                password=self.config.dump_config.admin_pw,
                auto_bind=True,
                client_strategy=ldap3.SYNC,
                auto_range=True,
                read_only=True,
            )
        except ldap3.core.exceptions.LDAPBindError as e:
            raise LdapErrorException(e)
        except ldap3.core.exceptions.LDAPSocketOpenError as e:
            cert_error = self.__parse_certificate_error(e)
            if cert_error:
                raise LdapErrorException(cert_error)
            raise LdapErrorException(e)

        return

    def __parse_certificate_error(self,exception):
        message = str(exception)
        match = re.match(r"socket ssl wrapping error: certificate {(.*)} .* in \[(.*)\]",
                     message,
                     re.IGNORECASE)
        if match:
            cert_str = "{" + match.group(1) + "}"
            cert = ast.literal_eval(cert_str)
            cert_subject= str(cert['subject'])
            names_str = "[" + match.group(2) + "]"
            names = ast.literal_eval(names_str)
            names_joined = ",".join(names)
            msg = "certificate error: subject does not match hostnames: {} subject: {}".format(names_joined,cert_subject)
            return msg
        else:
            return False

    def _test_naming_contexts(self):
        if self.config.dump_config.test_target_base_dn not in self.server.info.naming_contexts:
            r = ["the AD server does not have the naming context for {}".format(
                self.config.dump_config.test_target_base_dn)]
            r.append("supported naming contexts are:")
            r = r + self.server.info.naming_contexts
            msg = "\n".join(r)
            raise TestFailedException(msg)
        return


