# Python-version of krb5.conf reader
# ported from https://github.com/jcmturner/gokrb5/blob/master/v8/config/krb5conf.go
import ipaddress
from distutils.util import strtobool
import os
import re
from datetime import timedelta
from pathlib import Path
from pyasn1.type import univ
from pytimeparse import parse as time_parse

from pycquery_krb.common.creds import KerberosCredential

LIBDEFAULTS = "libdefaults"
REALMS = "realms"
DOMAIN_REALM = "domain_realm"
_IGNORED_SECTION = "ignored_section"

_SECTION_REG_STR = """^\s*\[{}\]\s*"""
_comment_rep = re.compile("""^\s*(#|;|\n)""")
_libdefaults_rep = re.compile(_SECTION_REG_STR.format(LIBDEFAULTS))
_realms_rep = re.compile(_SECTION_REG_STR.format(REALMS))
_domain_realm_rep = re.compile(_SECTION_REG_STR.format(DOMAIN_REALM))
_ignored_section_rep = re.compile(_SECTION_REG_STR.format(".*"))

# A set of encryption types that have been deemed weak.
weak_etype_set =\
    set("des-cbc-crc des-cbc-md4 des-cbc-md5 des-cbc-raw des3-cbc-raw des-hmac-sha1 arcfour-hmac-exp rc4-hmac-exp arcfour-hmac-md5-exp des".split())

_ENV_KRB5CONFIG = 'KRB5_CONFIG'
# http://web.mit.edu/kaduk/Public/doc/mitK5defaults.html#paths
_ENV_DEFAULT_KRB5CCNAME = ['/tmp/krb5cc_%{uid}']
_ENV_DEFAULT_KRB5CONFIG = ['/etc/krb5.conf', '/usr/local/etc/krb5.conf']


class InvalidSyntaxError(Exception):
    def __init__(self, msg):
        super().__init__(msg)


class _InnerUtil:
    @staticmethod
    def strip_comment(line):
        line = line.strip()

        # Remove comments after the values
        idx = line.find('#')
        if idx > -1:
            line = line[:idx]
        else:
            idx = line.find(';')
            if idx > -1:
                line = line[:idx]

        return line

    @staticmethod
    def parse_kv(line):
        if "=" not in line:
            raise InvalidSyntaxError("= is missing in ({})".format(line))

        p = line.split('=')
        key = p[0].strip().lower()
        value = p[1].strip()
        return key, value

    @staticmethod
    def parse_boolean(s):
        return bool(strtobool(s))

    @staticmethod
    def parse_duration(s):
        try:
            # handle N
            return timedelta(seconds=int(s))
        except:
            # handle Nd[NmNs], h:m[:s]
            return timedelta(seconds=time_parse(s))

    @staticmethod
    def parse_etypes(enctypes, allow_weak_crypto):
        enctype_ids = []
        for et in enctypes:
            if not allow_weak_crypto:
                if et in weak_etype_set:
                    continue
            i = KerberosCredential.etype_supported(et)
            if i:
                enctype_ids.append(i)
        return enctype_ids

    # Parse array of strings but stop if an asterisk is placed at the end of a line.
    @staticmethod
    def append_until_final(str_list, value):
        final = False
        last = len(value) - 1
        if last >= 0 and value[last] == '*':
            final = True
            value = value[:len(value) - 1]
        str_list.append(value)
        return final


# LibDefaults represents the [libdefaults] section of the configuration.
class LibDefaults:
    def __init__(self):
        uid = os.getuid()
        homedir = str(Path.home())
        # self.ap_req_checksum_type = 0
        self.allow_weak_crypto = False
        self.canonicalize = False
        self.ccache_type = 4
        self.clockskew = timedelta(seconds=300)  # max allowed skew in seconds, default 300
        self.default_ccache_name = _ENV_DEFAULT_KRB5CCNAME[0]
        self.default_client_keytab_name = "/usr/local/var/krb5/user/{}/client.keytab".format(uid)
        self.default_keytab_name = "/etc/krb5.keytab"
        self.default_realm = None
        self.default_tgs_enctypes = ["aes256-cts-hmac-sha1-96", "aes128-cts-hmac-sha1-96", "des3-cbc-sha1",
                                     "arcfour-hmac-md5", "camellia256-cts-cmac", "camellia128-cts-cmac", "des-cbc-crc",
                                     "des-cbc-md5", "des-cbc-md4"]
        self.default_tkt_enctypes = ["aes256-cts-hmac-sha1-96", "aes128-cts-hmac-sha1-96", "des3-cbc-sha1",
                                     "arcfour-hmac-md5", "camellia256-cts-cmac", "camellia128-cts-cmac", "des-cbc-crc",
                                     "des-cbc-md5", "des-cbc-md4"]
        self.default_tgs_enctype_ids = None
        self.default_tkt_enctype_ids = None
        self.dns_canonicalize_hostname = True
        self.dns_lookup_kdc = False
        self.dns_lookup_realm = False
        self.extra_addresses = []
        self.forwardable = False
        self.ignore_acceptor_hostname = False
        self.k5_login_authoritative = False
        self.k5_login_directory = homedir
        self.kdc_default_options = univ.BitString.fromHexString('00000010')  # KDC_OPT_RENEWABLE_OK
        self.kdc_time_sync = 1
        # self.kdc_req_checksum_type int //unlikely to implement as for very old KDCs
        self.no_addresses = False
        self.permitted_enctypes = ["aes256-cts-hmac-sha1-96", "aes128-cts-hmac-sha1-96", "des3-cbc-sha1",
                                   "arcfour-hmac-md5", "camellia256-cts-cmac", "camellia128-cts-cmac", "des-cbc-crc",
                                   "des-cbc-md5", "des-cbc-md4"]
        self.permitted_enctype_ids = None
        # self.plugin_base_dir //not supporting plugins
        self.preferred_preauth_types = [17, 16, 15, 14]
        self.proxiable = False
        self.rdns = True
        self.realm_try_domains = -1
        self.renew_lifetime = 0
        self.safe_checksum_type = 8
        self.ticket_lifetime = timedelta(days=1)
        self.udp_preference_limit = 1
        self.verify_ap_req_nofail = False

    def parse_lines(self, lines):
        for line in lines:
            line = _InnerUtil.strip_comment(line)
            if line == "":
                continue

            key, value = _InnerUtil.parse_kv(line)
            try:
                if "allow_weak_crypto" == key:
                    self.allow_weak_crypto = _InnerUtil.parse_boolean(value)
                elif "canonicalize" == key:
                    self.canonicalize = _InnerUtil.parse_boolean(value)
                elif "ccache_type" == key:
                    v = int(value)
                    if v < 0 or v > 4:
                        raise ValueError("ccache_type must be between 0 and 4")
                    self.ccache_type = v
                elif "clockskew" == key:
                    self.clockskew = _InnerUtil.parse_duration(value)
                elif "default_ccache_name" == key:
                    self.default_ccache_name = value
                elif "default_client_keytab_name" == key:
                    self.default_client_keytab_name = value
                elif "default_keytab_name" == key:
                    self.default_keytab_name = value
                elif "default_realm" == key:
                    self.default_realm = value
                elif "default_tgs_enctypes" == key:
                    self.default_tgs_enctypes = value.split()
                elif "default_tkt_enctypes" == key:
                    self.default_tkt_enctypes = value.split()
                elif "dns_canonicalize_hostname" == key:
                    self.dns_canonicalize_hostname = _InnerUtil.parse_boolean(value)
                elif "dns_lookup_kdc" == key:
                    self.dns_lookup_kdc = _InnerUtil.parse_boolean(value)
                elif "dns_lookup_realm" == key:
                    self.dns_lookup_realm = _InnerUtil.parse_boolean(value)
                elif "extra_addresses" == key:
                    for ipiddr in value.split(','):
                        self.extra_addresses.append(ipaddress.ip_address(ipiddr))
                elif "forwardable" == key:
                    self.forwardable = _InnerUtil.parse_boolean(value)
                elif "ignore_acceptor_hostname" == key:
                    self.ignore_acceptor_hostname = _InnerUtil.parse_boolean(value)
                elif "k5login_authoritative" == key:
                    self.k5_login_authoritative = _InnerUtil.parse_boolean(value)
                elif "k5login_directory" == key:
                    self.k5login_directory = value
                elif "kdc_default_options" == key:
                    v = value.replace("0x", "")
                    self.kdc_default_options = univ.BitString.fromHexString(v)
                elif "kdc_timesync" == key:
                    v = int(value)
                    if v < 0:
                        raise ValueError("kdc_timesync must not be negative")
                    self.kdc_time_sync = v
                elif "noaddresses" == key:
                    self.no_addresses = _InnerUtil.parse_boolean(value)
                elif "permitted_enctypes" == key:
                    self.permitted_enctypes = value.split()
                elif "preferred_preauth_types" == key:
                    for v in value.split(','):
                        self.preferred_preauth_types.append(int(v))
                elif "proxiable" == key:
                    self.proxiable = _InnerUtil.parse_boolean(value)
                elif "rdns" == key:
                    self.rdns = _InnerUtil.parse_boolean(value)
                elif "realm_try_domains" == key:
                    v = int(value)
                    if v < 0:
                        raise ValueError("realm_try_domains must not be negative")
                    self.realm_try_domains = v
                elif "renew_lifetime" == key:
                    self.renew_lifetime = _InnerUtil.parse_duration(value)
                elif "safe_checksum_type" == key:
                    v = int(value)
                    if v < 0:
                        raise ValueError("safe_checksum_type must not be negative")
                    self.safe_checksum_type = v
                elif "ticket_lifetime" == key:
                    self.ticket_lifetime = _InnerUtil.parse_duration(value)
                elif "udp_preference_limit" == key:
                    v = int(value)
                    if v > 32700:
                        raise ValueError("udp_preference_limit must be less than 32700")
                    self.udp_preference_limit = v
                elif "verify_ap_req_nofail" == key:
                    self.verify_ap_req_nofail = _InnerUtil.parse_boolean(value)
            except Exception as e:
                raise InvalidSyntaxError("libdefaults section line ({})".format(line)) from e

        self.default_tgs_enctype_ids = _InnerUtil.parse_etypes(self.default_tgs_enctypes, self.allow_weak_crypto)
        self.default_tkt_enctype_ids = _InnerUtil.parse_etypes(self.default_tkt_enctypes, self.allow_weak_crypto)
        self.permitted_enctype_ids = _InnerUtil.parse_etypes(self.permitted_enctypes, self.allow_weak_crypto)


# Realm represents an entry in the [realms] section of the configuration.
class Realm:
    def __init__(self):
        self.realm = ""
        self.admin_server = []
        self.default_domain = ""
        self.kdc = []
        self.kpasswd_server = []
        self.master_kdc = []

    def parse_lines(self, lines):
        is_admin_server_final_met = False
        is_kdc_final_met = False
        is_kpasswd_server_final_met = False
        is_master_kdc_final_met = False
        ignore = False
        c = 0  # counts the depth of blocks within brackets { }

        for line in lines:
            if ignore and c > 0 and ('{' not in line) and ('}' not in line):
                continue

            line = _InnerUtil.strip_comment(line)
            if line == "":
                continue

            if ('=' not in line) and ('}' not in line):
                raise InvalidSyntaxError("realms section line ({})".format(line))

            if 'v4_' in line:
                ignore = True
                err = "v4 configurations are not supported"

            if '{' in line:
                c = c + 1
                if ignore:
                    continue

            if '}' in line:
                c = c - 1
                if c < 0:
                    raise InvalidSyntaxError("unpaired curly brackets")
                if ignore:
                    if c < 1:
                        ignore = False
                    continue

            key, value = _InnerUtil.parse_kv(line)
            if "admin_server" == key:
                if is_admin_server_final_met:
                    continue
                is_admin_server_final_met = _InnerUtil.append_until_final(self.admin_server, value)
            elif "default_domain" == key:
                self.default_domain = value
            elif "kdc" == key:
                if is_kdc_final_met:
                    continue
                if ':' not in value:
                    # No port number specified default to 88
                    if value.endswith('*'):
                        value = value.rstrip('*').strip() + ":88*"
                    else:
                        value = value.strip() + ":88"
                is_kdc_final_met = _InnerUtil.append_until_final(self.kdc, value)
            elif "kpasswd_server" == key:
                if is_kpasswd_server_final_met:
                    continue
                is_kpasswd_server_final_met = _InnerUtil.append_until_final(self.kpasswd_server, value)
            elif "master_kdc" == key:
                if is_master_kdc_final_met:
                    continue
                is_master_kdc_final_met = _InnerUtil.append_until_final(self.master_kdc, value)

        # default for kpasswd_server = admin_server:464
        if len(self.kpasswd_server) < 1:
            for admin_server in self.admin_server:
                p = admin_server.split(":")
                self.kpasswd_server.append(p[0].strip() + ":464")


class KerberosConf:
    def __init__(self):
        self.lib_defaults = LibDefaults()
        self.realms = []
        # domain_realm maps the domains to realms representing the [domain_realm] section of the configuration.
        self.domain_realm = {}

    def parse_realms(self, lines):
        c = 0
        start = 0
        name = ""

        for i, line in enumerate(lines):
            line = _InnerUtil.strip_comment(line)
            if line == "":
                continue

            if "{" in line:
                c = c + 1
                if "=" not in line:
                    raise InvalidSyntaxError("= is missing : realm section line ({})".format(line))
                if c == 1:
                    start = i
                    p = line.split("=")
                    name = p[0].strip()

            if "}" in line:
                if c < 1:
                    raise InvalidSyntaxError("{ is missing")
                c = c - 1
                if c == 0:
                    realm = Realm()
                    realm.realm = name
                    realm.parse_lines(lines[start + 1:i])
                    self.realms.append(realm)

    def parse_domain_realm(self, lines):
        for line in lines:
            line = _InnerUtil.strip_comment(line)
            if line == "":
                continue

            key, value = _InnerUtil.parse_kv(line)
            self.domain_realm[key] = value

    def find_realm(self, realm_name):
        for realm in self.realms:
            if realm.realm == realm_name:
                return realm
        return None

    @staticmethod
    def from_osenv():
        krbconf = None

        config_path = os.environ.get(_ENV_KRB5CONFIG, default='')
        if len(config_path) > 0 and os.path.exists(config_path):
            return KerberosConf.from_file(config_path)

        if krbconf is None:
            for default_config_path in _ENV_DEFAULT_KRB5CONFIG:
                if os.path.exists(default_config_path):
                    return KerberosConf.from_file(default_config_path)

        return krbconf

    @staticmethod
    def from_file(path):
        with open(path, 'r') as file:
            content = file.read()

        return KerberosConf.from_string(content)

    @staticmethod
    def from_string(content):
        sections = {}
        section_line_nums = []

        org_lines = content.splitlines()
        lines = []
        for i, line in enumerate(org_lines):
            current_lines_len = len(lines)
            if _comment_rep.match(line):  # ignore comments and blank lines
                continue
            elif _libdefaults_rep.match(line):
                sections[current_lines_len] = LIBDEFAULTS
                section_line_nums.append(current_lines_len)
            elif _realms_rep.match(line):
                sections[current_lines_len] = REALMS
                section_line_nums.append(current_lines_len)
            elif _domain_realm_rep.match(line):
                sections[current_lines_len] = DOMAIN_REALM
                section_line_nums.append(current_lines_len)
            elif _ignored_section_rep.match(line):
                sections[current_lines_len] = _IGNORED_SECTION
                section_line_nums.append(current_lines_len)
            else:
                lines.append(line)

        conf = KerberosConf()

        for i, start in enumerate(section_line_nums):
            if i + 1 >= len(section_line_nums):
                end = len(lines)
            else:
                end = section_line_nums[i + 1]

            {
                LIBDEFAULTS: lambda l: conf.lib_defaults.parse_lines(l),
                REALMS: lambda l: conf.parse_realms(l),
                DOMAIN_REALM: lambda l: conf.parse_domain_realm(l),
                _IGNORED_SECTION: lambda l: l  # just throw it away
            }[sections[start]](lines[start:end])

        return conf


if __name__ == '__main__':
    filename = '/etc/krb5.conf'
    with open(filename, 'r') as f:
        data = f.read()

    krbconf = KerberosConf.from_string(data)
    print(krbconf.lib_defaults.kdc_default_options)
    print(krbconf.realms[0].kdc)
    print(krbconf.realms[1].master_kdc)
    print(krbconf.realms[2].realm)
    print(krbconf.realms[3].kdc)
    print(krbconf.realms[3].master_kdc)
