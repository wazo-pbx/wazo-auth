# -*- coding: utf-8 -*-
#
# Copyright (C) 2015 Avencall
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>

import copy

from xivo_auth import BaseAuthenticationBackend


class XiVOService(BaseAuthenticationBackend):

    def __init__(self, config):
        self.services = config.get('services', {})

    def get_consul_acls(self, login, args):
        service = self.services.get(login, {})
        acls = copy.deepcopy(service.get('acls', []))

        identifier, _ = self.get_ids(login, args)
        for acl in acls:
            acl['rule'] = acl['rule'].format(identifier=identifier)

        return acls

    def get_acls(self, login, args):
        return ['acl:dird']

    def get_ids(self, login, args):
        user_uuid = args.get('backend_args', {}).get('xivo_user_uuid', None)
        return user_uuid, user_uuid

    def verify_password(self, login, password):
        service = self.services.get(login, None)
        if not service:
            return False

        if service.get('secret', None) == password:
            return True
        return False