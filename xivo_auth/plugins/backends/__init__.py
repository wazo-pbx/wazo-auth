# -*- coding: utf-8 -*-
#
# Copyright (C) 2015-2016 Avencall
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

from .xivo_admin import XiVOAdmin  # noqa
from .xivo_service import XiVOService  # noqa
from .xivo_user import XiVOUser  # noqa
from .ldap_user_voicemail import LDAPUserVoicemail  # noqa
from .mock import BackendMock, BackendMockWithUUID  # noqa
from .broken import BrokenInitBackend  # noqa
from .broken import BrokenVerifyPasswordBackend  # noqa
