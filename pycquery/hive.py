"""DB-API implementation backed by HiveServer2 (Thrift API)

See http://www.python.org/dev/peps/pep-0249/

Many docstrings in this file are based on the PEP, which is in the public domain.
"""

from __future__ import absolute_import
from __future__ import unicode_literals

import atexit
import copy
import datetime
import random
import re
import threading
import configparser
import os
import io

from decimal import Decimal

from requests.auth import HTTPBasicAuth
from requests.models import Request

from TCLIService import TCLIService
from TCLIService import constants
from TCLIService import ttypes
from pycquery import common
from pycquery.common import DBAPITypeObject
# Make all exceptions visible in this module per DB-API
from pycquery.exc import *  # noqa
from builtins import range
import contextlib
from future.utils import iteritems
import getpass
import logging
import sys
import thrift.protocol.TBinaryProtocol
import thrift.transport.THttpClient
import thrift.transport.TSocket
import thrift.transport.TTransport

from pycquery_krb.common.creds import KerberosCredential
from pycquery_krb.common.target import KerberosTarget
from pycquery_krb.common.constants import KerberosSocketType
from pycquery_krb.client import KerbrosClient
from pycquery_krb.common.ccache import CCACHE
from pycquery_krb.common.spn import KerberosSPN
from pycquery_krb.protocol.structures import KRB5Token

# PEP 249 module globals
apilevel = '2.0'
threadsafety = 2  # Threads may share the module and connections.
paramstyle = 'pyformat'  # Python extended format codes, e.g. ...WHERE name=%(name)s

_logger = logging.getLogger(__name__)

_TIMESTAMP_PATTERN = re.compile(r'(\d+-\d+-\d+ \d+:\d+:\d+(\.\d{,6})?)')

_ENV_KRB5CCNAME = 'KRB5CCNAME'
_ENV_KRB5CONFIG = 'KRB5_CONFIG'


def _get_krb5_config_value_with_variable(value):
    return value.replace('%{uid}', str(os.getuid()))


def _parse_timestamp(value):
    if value:
        match = _TIMESTAMP_PATTERN.match(value)
        if match:
            if match.group(2):
                format = '%Y-%m-%d %H:%M:%S.%f'
                # use the pattern to truncate the value
                value = match.group()
            else:
                format = '%Y-%m-%d %H:%M:%S'
            value = datetime.datetime.strptime(value, format)
        else:
            raise Exception(
                'Cannot convert "{}" into a datetime'.format(value))
    else:
        value = None
    return value


TYPES_CONVERTER = {"DECIMAL_TYPE": Decimal,
                   "TIMESTAMP_TYPE": _parse_timestamp}


class HiveParamEscaper(common.ParamEscaper):
    def escape_string(self, item):
        # backslashes and single quotes need to be escaped
        # TODO verify against parser
        # Need to decode UTF-8 because of old sqlalchemy.
        # Newer SQLAlchemy checks dialect.supports_unicode_binds before encoding Unicode strings
        # as byte strings. The old version always encodes Unicode as byte strings, which breaks
        # string formatting here.
        if isinstance(item, bytes):
            item = item.decode('utf-8')
        return "'{}'".format(
            item
            .replace('\\', '\\\\')
            .replace("'", "\\'")
            .replace('\r', '\\r')
            .replace('\n', '\\n')
            .replace('\t', '\\t')
        )


_escaper = HiveParamEscaper()


def connect(*args, **kwargs):
    """Constructor for creating a connection to the database. See class :py:class:`Connection` for
    arguments.

    :returns: a :py:class:`Connection` object.
    """
    return Connection(*args, **kwargs)


class Connection(object):
    """Wraps a Thrift session"""

    def __init__(self, host=None, port=None, username=None, database='default', auth=None,
                 configuration=None, kerberos_service_name=None, password=None,
                 thrift_transport=None, service_mode='binary', http_path=None,
                 is_zookeeper=False, zookeeper_name_space='hiveserver2', keytab_file=None,
                 krb_conf=None):
        """Connect to HiveServer2

        :param host: What host HiveServer2 runs on
        :param port: What port HiveServer2 runs on. Defaults to 10000.
        :param auth: The value of hive.server2.authentication used by HiveServer2.
            Defaults to ``NONE``.
        :param configuration: A dictionary of Hive settings (functionally same as the `set` command)
        :param kerberos_service_name: Use with auth='KERBEROS' only
        :param password: Use with auth='LDAP' or auth='CUSTOM' only
        :param thrift_transport: A ``TTransportBase`` for custom advanced usage.
            Incompatible with host, port, auth, kerberos_service_name, and password.
        :param service_mode: Set thrift transport mode ('http' or 'binary')
        :param http_path: Use with service_mode='http' only
        :param is_zookeeper: Set whether or not zookeeper method
        :param zookeeper_name_space: Use with service_mode='http' and is_zookeeper='true' only
        :param keytab_file: Use with service_mode='http' and auth='KERBEROS' only
        :param krb_conf: pycquery_krb.common.conf.KerberosConf instance. Use with service_mode='http' and auth='KERBEROS' only

        The way to support LDAP and GSSAPI is originated from cloudera/Impyla:
        https://github.com/cloudera/impyla/blob/255b07ed973d47a3395214ed92d35ec0615ebf62
        /impala/_thrift_api.py#L152-L160
        """
        self._opened = False
        self._kerberos_service_name = kerberos_service_name
        self.auth = auth
        self.username = username or getpass.getuser()
        self.password = password
        self.service_mode = service_mode
        self.keytab_file = keytab_file
        self.auth_lock = threading.Lock()
        self.realm = None
        self.kdc = None
        self.kerb_client = None
        self.krb_conf = krb_conf
        self.expired_time = 0
        configuration = configuration or {}
        last_exception = None

        # if (password is not None) != (auth in ('LDAP', 'CUSTOM')):
        #     raise ValueError("Password should be set if and only if in LDAP or CUSTOM mode; "
        #                      "Remove password or use one of those modes")
        if auth == 'KERBEROS':
            if kerberos_service_name is None:
                raise ValueError("kerberos_service_name must be set in KERBEROS mode")

            if krb_conf is None:
                raise ValueError("krb_conf must be set in KERBEROS mode")

            p = self.username.split('@')
            self.username = p[0]
            if len(p) > 1:
                self.realm = p[1]
            else:
                self.realm = krb_conf.lib_defaults.default_realm

            if self.realm is None:
                raise ValueError("Kerberos realm must be specified at username or krb5.conf in KERBEROS mode")

            conf_realm = krb_conf.find_realm(self.realm)
            if conf_realm is None:
                raise ValueError("No matching realm in krb5.conf")
            if len(conf_realm.kdc) == 0:
                raise ValueError("No kdc information in {} realm of krb5.conf".format(self.realm))

            # use the first kdc in the list for implementation simpleness
            p = conf_realm.kdc[0].split(':')
            self.kdc = {"host": p[0], "port": p[1]}

        if thrift_transport is not None:
            has_incompatible_arg = (
                host is not None
                or port is not None
                or auth is not None
                or kerberos_service_name is not None
                or password is not None
            )
            if has_incompatible_arg:
                raise ValueError("thrift_transport cannot be used with "
                                 "host/port/auth/kerberos_service_name/password")

        if is_zookeeper:
            # It randomly shuffles node information stored in zookeeper.
            remaining_nodes = self._get_hiveserver2_info_with_zookeeper(host, port, zookeeper_name_space)
            random.shuffle(remaining_nodes)
        else:
            # Direct access to host and port if not zookeeper.
            remaining_nodes = [{'host': host, 'port': port}]

        # Access nodes sequentially and if they fail, access other nodes.
        while len(remaining_nodes) > 0:
            node = remaining_nodes.pop()
            self.host = node['host']
            self.port = node['port']
            if thrift_transport is not None:
                self._transport = thrift_transport
            elif service_mode == 'binary':
                if self.port is None:
                    self.port = 10000
                if self.auth is None:
                    self.auth = 'NONE'
                socket = thrift.transport.TSocket.TSocket(self.host, self.port)
                if auth == 'NOSASL':
                    # NOSASL corresponds to hive.server2.authentication=NOSASL in hive-site.xml
                    self._transport = thrift.transport.TTransport.TBufferedTransport(socket)
                elif self.auth in ('LDAP', 'KERBEROS', 'NONE', 'CUSTOM', 'NOSASL'):
                    # Defer import so package dependency is optional
                    import sasl
                    import thrift_sasl

                    if self.auth == 'KERBEROS':
                        # KERBEROS mode in hive.server2.authentication is GSSAPI in sasl library
                        sasl_auth = 'GSSAPI'
                    else:
                        sasl_auth = 'PLAIN'
                        if self.password is None:
                            # Password doesn't matter in NONE mode, just needs to be nonempty.
                            self.password = 'x'

                    def sasl_factory():
                        sasl_client = sasl.Client()
                        sasl_client.setAttr('host', self.host)
                        if sasl_auth == 'GSSAPI':
                            sasl_client.setAttr('service', self.kerberos_service_name)
                        elif sasl_auth == 'PLAIN':
                            sasl_client.setAttr('username', username)
                            sasl_client.setAttr('password', password)
                        else:
                            raise AssertionError
                        sasl_client.init()
                        return sasl_client
                    self._transport = thrift_sasl.TSaslClientTransport(sasl_factory, sasl_auth, socket)

                else:
                    # All HS2 config options:
                    # https://cwiki.apache.org/confluence/display/Hive/Setting+Up+HiveServer2#SettingUpHiveServer2-Configuration
                    # PAM currently left to end user via thrift_transport option.
                    raise NotImplementedError(
                        "Only NONE, NOSASL, LDAP, KERBEROS, CUSTOM "
                        "authentication are supported with binary mode, got {}".format(auth))

            elif service_mode == 'http':
                if self.auth is None:
                    self.auth = 'NONE'

                if self.auth in ('NONE', 'LDAP', 'KERBEROS', 'CUSTOM'):
                    if self.password is None:
                        self.password = 'x'
                    self._transport = thrift.transport.THttpClient.THttpClient(
                        "http://{}:{}/{}".format(self.host, self.port, http_path)
                    )
                    if auth == 'KERBEROS':
                        self.set_auth_setting()
                    else:
                        auth_header = HTTPBasicAuth(username, self.password)
                        self._transport.setCustomHeaders(auth_header(Request()).headers)
                else:
                    raise NotImplementedError(
                        "Only NONE, NOSASL, LDAP, KERBEROS, CUSTOM "
                        "authentication is supported with http mode, got {}".format(auth))
            else:
                raise NotImplementedError(
                    "Only binary, http are supported for the transport mode, "
                    "got {}".format(service_mode)
                )

            protocol = thrift.protocol.TBinaryProtocol.TBinaryProtocol(self._transport)
            self._client = TCLIService.Client(protocol)
            # oldest version that still contains features we care about
            # "V6 uses binary type for binary payload (was string) and uses columnar result set"
            protocol_version = ttypes.TProtocolVersion.HIVE_CLI_SERVICE_PROTOCOL_V6

            try:
                self._transport.open()
                open_session_req = ttypes.TOpenSessionReq(
                    client_protocol=protocol_version,
                    configuration=configuration,
                    username=username,
                )
                response = self._client.OpenSession(open_session_req)
                _check_status(response)
                assert response.sessionHandle is not None, "Expected a session from OpenSession"
                self._sessionHandle = response.sessionHandle
                assert response.serverProtocolVersion == protocol_version, \
                    "Unable to handle protocol version {}".format(response.serverProtocolVersion)
                self._opened = True
                with contextlib.closing(self.cursor()) as cursor:
                    cursor.execute('USE `{}`'.format(database))
                atexit.register(self.close)
            except Exception as ex:
                import traceback
                # If the node fails to access, it will try to reconnect to the remaining node.
                _logger.warning('Failed to connect to %s:%s. (message = %s)'
                                % (self.host, self.port, 'Error opening session' if isinstance(ex, EOFError) else ex))
                last_exception = ex
                self.close()
            else:
                # If any of the remaining nodes passed to zookeeper is successful, return.
                _logger.info('Connected to %s:%s' % (self.host, self.port))
                return

        # Return the last error I received.
        raise last_exception

    def __enter__(self):
        """Transport should already be opened by __init__"""
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Call close"""
        self.close()

    def close(self):
        """Close the underlying session and Thrift transport"""
        if self._opened:
            self.set_auth_setting()
            req = ttypes.TCloseSessionReq(sessionHandle=self._sessionHandle)
            response = self._client.CloseSession(req)
            self._transport.close()
            _check_status(response)
            self._opened = False

    def commit(self):
        """Hive does not support transactions, so this does nothing."""
        pass

    def cursor(self, *args, **kwargs):
        """Return a new :py:class:`Cursor` object using the connection."""
        return Cursor(self, *args, **kwargs)

    @property
    def client(self):
        return self._client

    @property
    def sessionHandle(self):
        return self._sessionHandle

    @property
    def kerberos_service_name(self):
        return self._kerberos_service_name.replace('_HOST', self.host)

    def rollback(self):
        raise NotSupportedError("Hive does not have transactions")  # pragma: no cover

    def set_auth_setting(self):
        if self.service_mode == 'http' and self.auth == 'KERBEROS':
            self.auth_lock.acquire()
            try:
                if self.kerb_client is None or self.expired_time < int(datetime.datetime.now().timestamp()):
                    if self.keytab_file:
                        self.kerb_client, self.expired_time = self._get_krb_client_with_keytab(self.username,
                                                                                               self.realm)
                    else:
                        # 1. Check the ccache environment variable.
                        c_path = os.environ.get(_ENV_KRB5CCNAME, default='')
                        # 2. Check the config variable.
                        if c_path == '':
                            c_path = _get_krb5_config_value_with_variable(self.krb_conf.lib_defaults.default_ccache_name)
                        if c_path == '':
                            raise IOError('The krb5 ticket cache does not exist.')
                        self.kerb_client, self.expired_time = self._get_krb_client_with_ccache(self.username,
                                                                                               self.realm, c_path)
                spn = KerberosSPN()
                spn.service = self.kerberos_service_name if self.kerberos_service_name.count('/') == 1 \
                    else self.kerberos_service_name + '/' + self.host
                spn.domain = self.realm
                tgs, enc, key = self.kerb_client.get_TGS(spn)
                token = self.kerb_client.construct_apreq(tgs=tgs, encTGSRepPart=enc, sessionkey=key, flags=0)
                headers = {'Authorization': 'Negotiate ' + KRB5Token(token).get_apreq_token()}
                self._transport.setCustomHeaders(headers)
            finally:
                self.auth_lock.release()

    def _get_krb_client_with_keytab(self, user, realm):
        cred = KerberosCredential.from_keytab(self.keytab_file, user, realm)
        target = KerberosTarget()
        target.ip = self.kdc['host']
        target.port = self.kdc['port']
        target.protocol = KerberosSocketType.TCP
        client = KerbrosClient(cred, target)
        client.get_TGT()
        return client, int(client.kerberos_TGT_encpart['endtime'].timestamp())

    def _get_krb_client_with_ccache(self, user, realm, c_path):
        try:
            with open(c_path, 'rb') as file:
                selected = next(iter(
                    filter(lambda cred: user in cred[0][0]['cname']['name-string'] and cred[0][0]['crealm'] == realm,
                           CCACHE.parse(io.BytesIO(bytearray(file.read()))).get_all_tgt())), None)
                target = KerberosTarget()
                target.ip = self.kdc['host']
                target.port = self.kdc['port']
                target.protocol = KerberosSocketType.TCP
                return KerbrosClient.from_tgt(target, selected[0][0], selected[0][1]), selected[1].endtime
        except Exception as ex:
            raise IOError('An error occurred during the ccache file loading process., %s' % ex)

    def _get_hiveserver2_info_with_zookeeper(self, host, port, zookeeper_name_space):
        """Get hiveserver2 URL information from zookeeper."""
        from kazoo.client import KazooClient
        from kazoo.retry import KazooRetry

        hosts = host.split(',')
        zk_hosts = ','.join(list(map(lambda x: ':'.join([x, str(port)]), hosts)))

        conn_retry_policy = KazooRetry(max_tries=-1, delay=0.1, max_delay=0.1)
        cmd_retry_policy = KazooRetry(max_tries=3, delay=0.3, backoff=1, max_delay=1, ignore_expire=False)
        zk = KazooClient(hosts=zk_hosts, connection_retry=conn_retry_policy, command_retry=cmd_retry_policy)

        zk.start()
        children = zk.get_children('/' + zookeeper_name_space)
        nodes = self.get_hiveserver2_info(children)
        zk.stop()
        zk.close()

        if len(nodes) == 0:
            from kazoo.exceptions import ZookeeperError
            raise ZookeeperError("Can not find child in zookeeper path({}).".format(zookeeper_name_space))

        return nodes

    @staticmethod
    def get_hiveserver2_info(children):
        """Change node information stored in zookeeper to dictionary type list"""
        result = list()
        for child in children:
            node = dict()
            for info in child.split(';'):
                (key, value) = info.split('=')
                if key == 'serverUri':
                    node['host'], node['port'] = value.split(':')
                else:
                    node[key] = value
            result.append(node)
        return result


class Cursor(common.DBAPICursor):
    """These objects represent a database cursor, which is used to manage the context of a fetch
    operation.

    Cursors are not isolated, i.e., any changes done to the database by a cursor are immediately
    visible by other cursors or connections.
    """

    def __init__(self, connection, arraysize=1000):
        self._operationHandle = None
        super(Cursor, self).__init__()
        self._arraysize = arraysize
        self._connection = connection

    def _reset_state(self):
        """Reset state about the previous query in preparation for running another query"""
        super(Cursor, self)._reset_state()
        self._description = None
        if self._operationHandle is not None:
            self._connection.set_auth_setting()
            request = ttypes.TCloseOperationReq(self._operationHandle)
            try:
                response = self._connection.client.CloseOperation(request)
                _check_status(response)
            finally:
                self._operationHandle = None

    @property
    def arraysize(self):
        return self._arraysize

    @arraysize.setter
    def arraysize(self, value):
        """Array size cannot be None, and should be an integer"""
        default_arraysize = 1000
        try:
            self._arraysize = int(value) or default_arraysize
        except TypeError:
            self._arraysize = default_arraysize

    @property
    def description(self):
        """This read-only attribute is a sequence of 7-item sequences.

        Each of these sequences contains information describing one result column:

        - name
        - type_code
        - display_size (None in current implementation)
        - internal_size (None in current implementation)
        - precision (None in current implementation)
        - scale (None in current implementation)
        - null_ok (always True in current implementation)

        This attribute will be ``None`` for operations that do not return rows or if the cursor has
        not had an operation invoked via the :py:meth:`execute` method yet.

        The ``type_code`` can be interpreted by comparing it to the Type Objects specified in the
        section below.
        """
        if self._operationHandle is None or not self._operationHandle.hasResultSet:
            return None
        if self._description is None:
            self._connection.set_auth_setting()
            req = ttypes.TGetResultSetMetadataReq(self._operationHandle)
            response = self._connection.client.GetResultSetMetadata(req)
            _check_status(response)
            columns = response.schema.columns
            self._description = []
            for col in columns:
                primary_type_entry = col.typeDesc.types[0]
                if primary_type_entry.primitiveEntry is None:
                    # All fancy stuff maps to string
                    type_code = ttypes.TTypeId._VALUES_TO_NAMES[ttypes.TTypeId.STRING_TYPE]
                else:
                    type_id = primary_type_entry.primitiveEntry.type
                    type_code = ttypes.TTypeId._VALUES_TO_NAMES[type_id]
                self._description.append((
                    col.columnName.decode('utf-8') if sys.version_info[0] == 2 else col.columnName,
                    type_code.decode('utf-8') if sys.version_info[0] == 2 else type_code,
                    None, None, None, None, True
                ))
        return self._description

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()

    def close(self):
        """Close the operation handle"""
        self._reset_state()

    def execute(self, operation, parameters=None, **kwargs):
        """Prepare and execute a database operation (query or command).

        Return values are not defined.
        """
        # backward compatibility with Python < 3.7
        for kw in ['async', 'async_']:
            if kw in kwargs:
                async_ = kwargs[kw]
                break
        else:
            async_ = False

        for kw in ['config', 'config_']:
            if kw in kwargs:
                config_ = kwargs[kw]
                break
        else:
            config_ = copy.deepcopy(self.confOverlay) if hasattr(self, 'confOverlay') else {}

        if 'hivevar' in kwargs and isinstance(kwargs['hivevar'], dict) and hasattr(self, 'set_hivevar'):
            self.set_hivevar(kwargs['hivevar'])

        # Prepare statement
        if parameters is None:
            sql = operation
        else:
            sql = operation % _escaper.escape_args(parameters)

        self._reset_state()

        self._state = self._STATE_RUNNING
        self._connection.set_auth_setting()
        req = ttypes.TExecuteStatementReq(self._connection.sessionHandle,
                                          sql, runAsync=async_, confOverlay=config_)
        _logger.debug(req)
        response = self._connection.client.ExecuteStatement(req)
        _check_status(response)
        self._operationHandle = response.operationHandle

    def cancel(self):
        self._connection.set_auth_setting()
        req = ttypes.TCancelOperationReq(
            operationHandle=self._operationHandle,
        )
        response = self._connection.client.CancelOperation(req)
        _check_status(response)

    def _fetch_more(self):
        """Send another TFetchResultsReq and update state"""
        assert(self._state == self._STATE_RUNNING), "Should be running when in _fetch_more"
        assert(self._operationHandle is not None), "Should have an op handle in _fetch_more"
        if not self._operationHandle.hasResultSet:
            raise ProgrammingError("No result set")
        self._connection.set_auth_setting()
        req = ttypes.TFetchResultsReq(
            operationHandle=self._operationHandle,
            orientation=ttypes.TFetchOrientation.FETCH_NEXT,
            maxRows=self.arraysize,
        )
        response = self._connection.client.FetchResults(req)
        _check_status(response)
        schema = self.description
        assert not response.results.rows, 'expected data in columnar format'
        columns = [_unwrap_column(col, col_schema[1]) for col, col_schema in
                   zip(response.results.columns, schema)]
        new_data = list(zip(*columns))
        self._data += new_data
        # response.hasMoreRows seems to always be False, so we instead check the number of rows
        # https://github.com/apache/hive/blob/release-1.2.1/service/src/java/org/apache/hive/service/cli/thrift/ThriftCLIService.java#L678
        # if not response.hasMoreRows:
        if not new_data:
            self._state = self._STATE_FINISHED

    def poll(self, get_progress_update=True):
        """Poll for and return the raw status data provided by the Hive Thrift REST API.
        :returns: ``ttypes.TGetOperationStatusResp``
        :raises: ``ProgrammingError`` when no query has been started
        .. note::
            This is not a part of DB-API.
        """
        if self._state == self._STATE_NONE:
            raise ProgrammingError("No query yet")

        self._connection.set_auth_setting()
        req = ttypes.TGetOperationStatusReq(
            operationHandle=self._operationHandle,
            getProgressUpdate=get_progress_update,
        )
        response = self._connection.client.GetOperationStatus(req)
        _check_status(response)

        return response

    def fetch_logs(self):
        """Retrieve the logs produced by the execution of the query.
        Can be called multiple times to fetch the logs produced after the previous call.
        :returns: list<str>
        :raises: ``ProgrammingError`` when no query has been started
        .. note::
            This is not a part of DB-API.
        """
        if self._state == self._STATE_NONE:
            raise ProgrammingError("No query yet")

        try:  # Older Hive instances require logs to be retrieved using GetLog
            self._connection.set_auth_setting()
            req = ttypes.TGetLogReq(operationHandle=self._operationHandle)
            logs = self._connection.client.GetLog(req).log.splitlines()
        except ttypes.TApplicationException as e:  # Otherwise, retrieve logs using newer method
            if e.type != ttypes.TApplicationException.UNKNOWN_METHOD:
                raise
            logs = []
            while True:
                self._connection.set_auth_setting()
                req = ttypes.TFetchResultsReq(
                    operationHandle=self._operationHandle,
                    orientation=ttypes.TFetchOrientation.FETCH_NEXT,
                    maxRows=self.arraysize,
                    fetchType=1  # 0: results, 1: logs
                )
                response = self._connection.client.FetchResults(req)
                _check_status(response)
                assert not response.results.rows, 'expected data in columnar format'
                assert len(response.results.columns) == 1, response.results.columns
                new_logs = _unwrap_column(response.results.columns[0])
                logs += new_logs

                if not new_logs:
                    break

        return logs


#
# Type Objects and Constructors
#


for type_id in constants.PRIMITIVE_TYPES:
    name = ttypes.TTypeId._VALUES_TO_NAMES[type_id]
    setattr(sys.modules[__name__], name, DBAPITypeObject([name]))


#
# Private utilities
#


def _unwrap_column(col, type_=None):
    """Return a list of raw values from a TColumn instance."""
    for attr, wrapper in iteritems(col.__dict__):
        if wrapper is not None:
            result = wrapper.values
            nulls = wrapper.nulls  # bit set describing what's null
            assert isinstance(nulls, bytes)
            for i, char in enumerate(nulls):
                byte = ord(char) if sys.version_info[0] == 2 else char
                for b in range(8):
                    if byte & (1 << b):
                        result[i * 8 + b] = None
            converter = TYPES_CONVERTER.get(type_, None)
            if converter and type_:
                result = [converter(row) if row else row for row in result]
            return result
    raise DataError("Got empty column value {}".format(col))  # pragma: no cover


def _check_status(response):
    """Raise an OperationalError if the status is not success"""
    _logger.debug(response)
    if response.status.statusCode != ttypes.TStatusCode.SUCCESS_STATUS:
        raise OperationalError(response)
