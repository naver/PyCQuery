# Python-version of krb5.conf reader test
# ported from https://github.com/jcmturner/gokrb5/blob/master/v8/config/krb5conf_test.go

import unittest
from datetime import timedelta

from pycquery_krb.common.conf import KerberosConf, InvalidSyntaxError

kvpair_missing_conf = """
[libdefaults]
default_realm: TEST.PYCQUERY_KRB
[realms]
[domain_realm]
"""

wrong_boolean_conf = """
[libdefaults]
allow_weak_crypto=x
[realms]
[domain_realm]
"""

wrong_ccachetype_conf = """
[libdefaults]
ccache_type=5
[realms]
[domain_realm]
"""


class TestKRB5ConfParser(unittest.TestCase):
    def test_from_file(self):
        c = KerberosConf.from_file('test_data/test_krb5.conf')

        # check libdefaults
        self.assertEqual(False, c.lib_defaults.allow_weak_crypto)
        self.assertEqual("TEST.GOKRB5", c.lib_defaults.default_realm, "[libdefaults] default_realm not as expected")
        self.assertEqual(False, c.lib_defaults.dns_lookup_realm)
        self.assertEqual(False, c.lib_defaults.dns_lookup_kdc)
        self.assertEqual(timedelta(hours=10), c.lib_defaults.ticket_lifetime)
        self.assertEqual(True, c.lib_defaults.forwardable)
        self.assertEqual("FILE:/etc/krb5.keytab", c.lib_defaults.default_keytab_name)
        self.assertEqual("FILE:/home/gokrb5/client.keytab", c.lib_defaults.default_client_keytab_name)
        self.assertEqual(["aes256-cts-hmac-sha1-96", "aes128-cts-hmac-sha1-96"], c.lib_defaults.default_tkt_enctypes)

        # check realm
        self.assertEqual(3, len(c.realms))
        self.assertEqual("TEST.GOKRB5", c.realms[0].realm)
        self.assertEqual(["10.80.88.88:749"], c.realms[0].admin_server)
        self.assertEqual(["10.80.88.88:464"], c.realms[0].kpasswd_server)
        self.assertEqual("test.gokrb5", c.realms[0].default_domain)
        self.assertEqual(["10.80.88.88:88", "assume.port.num:88", "some.other.port:1234", "10.80.88.88:88"], c.realms[0].kdc)
        self.assertEqual(["kerberos.example.com:88", "kerberos-1.example.com:88"], c.realms[1].kdc)
        self.assertEqual(["kerberos.example.com"], c.realms[1].admin_server)
        self.assertEqual("lowercase.org", c.realms[2].realm)

        # check domain_realm
        self.assertEqual("TEST.GOKRB5", c.domain_realm[".test.gokrb5"])
        self.assertEqual("TEST.GOKRB5", c.domain_realm["test.gokrb5"])

    def test_kvpair_missing(self):
        self.assertRaises(InvalidSyntaxError, KerberosConf.from_string, kvpair_missing_conf)

    def test_wrong_boolean(self):
        self.assertRaises(InvalidSyntaxError, KerberosConf.from_string, wrong_boolean_conf)

    def test_wrong_ccache_type(self):
        self.assertRaises(InvalidSyntaxError, KerberosConf.from_string, wrong_ccachetype_conf)

    def test_v4lines_file(self):
        c = KerberosConf.from_file('test_data/test_v4lines_krb5.conf')

        # check libdefaults
        self.assertEqual("TEST.GOKRB5", c.lib_defaults.default_realm, "[libdefaults] default_realm not as expected")
        self.assertEqual(False, c.lib_defaults.dns_lookup_realm)
        self.assertEqual(False, c.lib_defaults.dns_lookup_kdc)
        self.assertEqual(timedelta(hours=10), c.lib_defaults.ticket_lifetime)
        self.assertEqual(True, c.lib_defaults.forwardable)
        self.assertEqual("FILE:/etc/krb5.keytab", c.lib_defaults.default_keytab_name)
        self.assertEqual("FILE:/home/gokrb5/client.keytab", c.lib_defaults.default_client_keytab_name)
        self.assertEqual(["aes256-cts-hmac-sha1-96", "aes128-cts-hmac-sha1-96"], c.lib_defaults.default_tkt_enctypes)

        # check realm
        self.assertEqual(2, len(c.realms))
        self.assertEqual("TEST.GOKRB5", c.realms[0].realm)
        self.assertEqual(["10.80.88.88:749"], c.realms[0].admin_server)
        self.assertEqual(["10.80.88.88:464"], c.realms[0].kpasswd_server)
        self.assertEqual("test.gokrb5", c.realms[0].default_domain)
        self.assertEqual(["10.80.88.88:88", "assume.port.num:88", "some.other.port:1234", "10.80.88.88:88"], c.realms[0].kdc)
        self.assertEqual(["kerberos.example.com:88", "kerberos-1.example.com:88"], c.realms[1].kdc)
        self.assertEqual(["kerberos.example.com"], c.realms[1].admin_server)

        # check domain_realm
        self.assertEqual("TEST.GOKRB5", c.domain_realm[".test.gokrb5"])
        self.assertEqual("TEST.GOKRB5", c.domain_realm["test.gokrb5"])

    def test_noblanklines_file(self):
        c = KerberosConf.from_file('test_data/test_noblanklines_krb5.conf')

        # check libdefaults
        self.assertEqual("TEST.GOKRB5", c.lib_defaults.default_realm, "[libdefaults] default_realm not as expected")
        self.assertEqual(False, c.lib_defaults.dns_lookup_realm)
        self.assertEqual(False, c.lib_defaults.dns_lookup_kdc)
        self.assertEqual(timedelta(hours=10), c.lib_defaults.ticket_lifetime)
        self.assertEqual(True, c.lib_defaults.forwardable)
        self.assertEqual("FILE:/etc/krb5.keytab", c.lib_defaults.default_keytab_name)
        self.assertEqual("FILE:/home/gokrb5/client.keytab", c.lib_defaults.default_client_keytab_name)
        self.assertEqual(["aes256-cts-hmac-sha1-96", "aes128-cts-hmac-sha1-96"], c.lib_defaults.default_tkt_enctypes)

        # check realm
        self.assertEqual(2, len(c.realms))
        self.assertEqual("TEST.GOKRB5", c.realms[0].realm)
        self.assertEqual(["10.80.88.88:749"], c.realms[0].admin_server)
        self.assertEqual(["10.80.88.88:464"], c.realms[0].kpasswd_server)
        self.assertEqual("test.gokrb5", c.realms[0].default_domain)
        self.assertEqual(["10.80.88.88:88", "assume.port.num:88", "some.other.port:1234", "10.80.88.88:88"], c.realms[0].kdc)
        self.assertEqual("EXAMPLE.COM", c.realms[1].realm)
        self.assertEqual(["kerberos.example.com:88", "kerberos-1.example.com:88"], c.realms[1].kdc)
        self.assertEqual(["kerberos.example.com"], c.realms[1].admin_server)

        # check domain_realm
        self.assertEqual("TEST.GOKRB5", c.domain_realm[".test.gokrb5"])
        self.assertEqual("TEST.GOKRB5", c.domain_realm["test.gokrb5"])


if __name__ == '__main__':
    unittest.main()
