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
from safeguard.sessions.plugin.plugin_base import PluginBase
from .Tpam import Tpam


class ConfigurationValidationError(RuntimeError):
    pass


class Plugin(PluginBase):
    def get_private_key_list(self, session_id, session_cookie, cookie, protocol, client_ip, gateway_username,
                             gateway_password, target_username, target_host, **kwargs):
        self.logger.info("Getting private keys is not implemented")
        return {'private_keys': []}

    def get_password_list(self, session_id, session_cookie, cookie, protocol, client_ip, gateway_username,
                          gateway_password, target_username, target_host, **kwargs):

        reuse_gateway_password = self.plugin_configuration.getboolean('tpam', 'reuse_gateway_password', False)
        if reuse_gateway_password and gateway_username == target_username:
            self.logger.info(
                "Gateway and target user are the same, no TPAM lookup needed. Using gateway user's password.")
            return self._create_reply(cookie, [gateway_password])

        pwlist = None
        try:
            pwlist = self._invoke_tpam(gateway_username, target_host, target_username)
        except Exception as e:
            self.logger.error("Exception occured: Error: %s: %s" % (e.__class__, str(e)))
        finally:
            return self._create_reply(cookie, pwlist)

    def _invoke_tpam(self, gateway_username, target_host, target_username):
        with Tpam.from_config(self.plugin_configuration) as tpam:
            # For the next query, we need system in prefix+HOSTNAME (e.g. PSM_HOSTNAME) format.
            system = (self.plugin_configuration.get('tpam', 'system_prefix', default='') +
                      self._resolve_system_name(tpam, target_host))

            reasontext = ",".join((gateway_username, "SPS"))  # TODO: PAM-8576 SPS -> get_gateway_fqdn()

            if self.plugin_configuration.getboolean('tpam', 'system_maptoreal', default=False):
                # A second lookup is need to get the real system and account info.
                info = tpam.get_real_sysacc_info(target_username, system)
                if info:
                    target_username = info['realaccount']
                    system = info['realsystem']
                else:
                    return

            (authorized, comment) = self._is_authorized(tpam, gateway_username, target_username, system)
            if not authorized:
                return

            reasontext = ','.join((reasontext, comment))

            password = tpam.get_password(target_username, system, reasontext)
            if password:
                return [password]

        self.logger.info("No password found.")

    def _resolve_system_name(self, tpam, system_ip_address):
        resolver = self.plugin_configuration.get('tpam', 'system_name_resolver', default='tpam').lower()

        if resolver == 'dns':
            return tpam.get_system_name_with_dns(system_ip_address)
        elif resolver == 'tpam':
            return tpam.get_system_name_with_tpam(system_ip_address)
        else:
            raise ConfigurationValidationError("Unknown system name resolver %s" % resolver)

    def _is_authorized(self, tpam, gateway_username, target_username, system):
        authorization = self.plugin_configuration.get('tpam', 'authorization', default='gateway').lower()
        required_policy = self.plugin_configuration.get('tpam', 'required_policy', default='Privileged Access')

        if authorization == 'gateway':
            return (True, 'gateway')
        elif authorization == 'approval':
            # Does the user have an active/approved request to work on target_host with target_username?
            request = tpam.get_request_details(gateway_username, target_username, system)
            if request is not None:
                return (True, 'approval,%s' % request['id'])
        elif authorization == 'policy':
            # Does the user have the required policy for the account/system ?
            if tpam.requestor_has_policy(gateway_username, target_username, system, required_policy):
                return (True, 'policy,%s' % required_policy)
        else:
            raise ConfigurationValidationError("Unknown authorization method %s" % authorization)
        return (False, None)

    def _create_reply(self, cookie, password_list):
        call_count = cookie['call_count'] if 'call_count' in cookie else 0
        return {'passwords': password_list if password_list else [], 'cookie': {'call_count': call_count + 1}}

    def authentication_completed(self, session_id, cookie):
        call_count = cookie["call_count"] if "call_count" in cookie else 0
        self.logger.info("Received notification about completed authentication. call_count: %s" % call_count)

    def session_ended(self, session_id, cookie):
        call_count = cookie["call_count"] if "call_count" in cookie else 0
        self.logger.info("Received notification about session end. call_count: %s" % call_count)
