#
#   Copyright (c) 2018-2019 One Identity
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to
# deal in the Software without restriction, including without limitation the
# rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
# sell copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
# FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
# IN THE SOFTWARE.
#
from io import StringIO
import paramiko
from safeguard.sessions.plugin import logging, CredentialStore
from safeguard.sessions.plugin.host_resolver import HostResolver
import tempfile


class APIConnError(Exception):
    pass


class SystemLookupError(Exception):
    pass


class Tpam:

    KEYTYPE_TO_PARAMIKO_KEYCLASS = {
        "ssh-dss": paramiko.DSSKey,
        "ssh-rsa": paramiko.RSAKey,
        "ecdsa-sha2-nistp256": paramiko.ECDSAKey,
    }

    def __init__(self, server, port, hostkey, user, user_key, host_resolver):
        self.log = logging.get_logger(__name__)
        self.server = server
        self.port = port
        self.hostkey = hostkey
        self.user = user
        self.user_key = user_key
        self.host_resolver = host_resolver
        self.conn = None

    @classmethod
    def from_config(cls, plugin_configuration):
        credential_store = CredentialStore.from_config(plugin_configuration)
        server_user_keys = credential_store.get_keys("tpam", "server_user_key")
        if not server_user_keys:
            raise RuntimeError("No server_user_key set!")
        return cls(
            plugin_configuration.get("tpam", "server", required=True),
            plugin_configuration.getint("tpam", "server_port", default=22),
            plugin_configuration.get("tpam", "server_public_key", required=True),
            plugin_configuration.get("tpam", "server_user", required=True),
            server_user_keys[0],
            HostResolver.from_config(plugin_configuration),
        )

    def __enter__(self):
        "Opens an SSH connection to TPAM and saves it to self.conn. Throws APIConnError if connection attempt fails."
        if self.conn:
            return

        try:
            self.log.info("Connecting via SSH to TPAM at %s:%i as user: '%s'." % (self.server, self.port, self.user))

            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.RejectPolicy())  # instead of AutoAddPolicy()
            self._load_host_key(ssh)
            dss_key = self._create_Pkey(self.user_key)
            ssh.connect(
                self.server, self.port, self.user, pkey=dss_key, allow_agent=False, look_for_keys=False, timeout=60
            )
            self.log.debug("SSH transport: " + repr(ssh.get_transport()))
            self.conn = ssh
        except Exception as e:
            raise APIConnError("TPAM connection error. Error: %s: %s" % (e.__class__, str(e)))
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        if self.conn is None:
            return

        try:
            self.log.info("Closing SSH connection to TPAM: '%s'." % repr(self.conn.get_transport()))
            self.conn.close()
            self.conn = None
        except Exception as e:
            raise APIConnError(
                "Failed to close SSH connection to %s:%i. Error: %s: %s" % (self.server, self.port, e.__class__, str(e))
            )

    def _load_host_key(self, ssh):
        self.log.debug("Loading hostkey: {}".format(self.hostkey))
        with TempHostKeyFile(self.hostkey) as hostfile:
            ssh.load_host_keys(hostfile.name)  # instead of load_system_host_keys()

    def _create_Pkey(self, server_user_cred):
        if not isinstance(server_user_cred, dict):
            self.log.error("TPAM server_user_key unusable, should be stored in a local credential store")
            return None

        keytype = server_user_cred["type"]
        self.log.debug("Using private key type {}".format(keytype))
        keyclass = self.KEYTYPE_TO_PARAMIKO_KEYCLASS[keytype]
        keyfile = StringIO(server_user_cred.get("key"))
        return keyclass.from_private_key(keyfile)

    def get_system_name_with_dns(self, system_ip_address):
        self.log.debug("Looking up TPAM system name from %s using reverse DNS" % system_ip_address)
        hosts = self.host_resolver.resolve_hosts_by_ip(system_ip_address)
        if hosts:
            # The initial lookup for active/approved requests (ListRequestDetails) expects PSM_HOSTNAME.
            return hosts[0].split(".")[0].upper()
        else:
            # If IP can't be resolved to a hostname, we can't continue.
            raise SystemLookupError("Failed to look up system name with DNS from: %s" % system_ip_address)

    def get_system_name_with_tpam(self, system_ip_address):
        self.log.debug("Looking up TPAM system name from %s using TPAM ListSystems call" % system_ip_address)
        (stdin, stdout, stderr) = self.conn.exec_command("ListSystems --NetworkAddress %s" % system_ip_address)
        response = stdout.readlines()

        if response[0].strip() != "No Systems to list":
            return response[1].split("\t")[0]
        else:
            raise SystemLookupError("Failed to look up system name with TPAM ListSystems from: %s" % system_ip_address)

    def get_request_details(self, requestor, account, system):
        "Queries TPAM for active and approved requests. Returns a dict of {'id', 'endtime'} or None."
        self.log.info(
            "Fetching request details for requestor: '%s' for account: '%s' on system: '%s'"
            % (requestor, account, system)
        )

        (stdin, stdout, stderr) = self.conn.exec_command(
            "ListRequestDetails --RequestorName %s --AccountName %s --SystemName %s --Status Active"
            % (requestor, account, system)
        )
        response = stdout.readlines()

        # Respose is either a 'No Request to list' or a 2+ item list: ['header', 'request', ...].
        if response[0].strip() != "No Requests to list":
            request = response[1].split("\t")
            # We only need 'request-id' and end time ('%Y-%m-%d %H:%M:%S.%f').
            return {"id": request[0], "endtime": request[12]}
        else:
            self.log.info("No active and valid request found.")

    def requestor_has_policy(self, requestor, account, system, required_policy):
        self.log.info(
            "Checking '%s' policy for requestor: '%s' for account: '%s' on system: '%s'"
            % (required_policy, requestor, account, system)
        )

        (stdin, stdout, stderr) = self.conn.exec_command(
            "ListAssignedPolicies "
            + "--UserName %s --AccountName %s --SystemName %s " % (requestor, account, system)
            + "--AllOrEffectiveFlag E --PermissionType Pwd"
        )
        response = stdout.readlines()

        if response[0].strip() != "No Permissions to list":
            for line in response[1:]:
                if line.split("\t")[9] == required_policy:
                    return True

        self.log.info("Requestor does not have the required policy")
        return False

    def get_real_sysacc_info(self, account, system):
        "Looks up real account and system name in TPAM. Returns a dict of {'realsystem', 'realaccount'} or None."
        self.log.info("Retrieving real account and system name for account: '%s' and system: '%s'" % (account, system))

        (stdin, stdout, stderr) = self.conn.exec_command(
            "ListAccounts --AccountName %s --SystemName %s" % (account, system)
        )
        response = stdout.readlines()

        # Response is either 'No Accounts to list' or a 2+ item list: ['header', 'accountinfo', ...].
        if response[0].strip() != "No Accounts to list":
            realinfo = dict(zip(response[0].split("\t"), response[1].split("\t")))
            realaccount = realinfo.get("AccountCustom1")
            realsystem = realinfo.get("AccountCustom2")

            if realaccount and realsystem:
                return {"realaccount": realaccount, "realsystem": realsystem}

        self.log.info("Could not find real system name and account info.")

    def get_password(self, realaccount, realsystem, reasontext):
        "Checks out password from TPAM. Returns a string of 'password'."
        self.log.info(
            "Checking out password for account: '%s' on server: '%s' reason: '%s'"
            % (realaccount, realsystem, reasontext)
        )

        (stdin, stdout, stderr) = self.conn.exec_command(
            'Retrieve --AccountName %s --SystemName %s --ReasonText "%s"' % (realaccount, realsystem, reasontext)
        )
        response = stdout.readlines()

        # Response is either a single line with '...not authorized...' or 'password'.
        return response[0].rstrip("\r\n") if response and "not authorized" not in response[0].lower() else None


class TempHostKeyFile:
    def __init__(self, hostkey):
        self.tempfile = tempfile.NamedTemporaryFile(mode="w+t", dir="/tmp")
        self.tempfile.write(hostkey)
        self.tempfile.flush()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        if self.tempfile:
            self.tempfile.close()

    @property
    def name(self):
        return self.tempfile.name
