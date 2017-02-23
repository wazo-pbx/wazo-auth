# -*- coding: utf-8 -*-
#
# Copyright 2017 The Wazo Authors  (see the AUTHORS file)
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program. If not, see <http://www.gnu.org/licenses/>

from sqlalchemy import (
    Column, ForeignKey, Integer, String, Text, text, UniqueConstraint,
)
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship

Base = declarative_base()


class ACL(Base):

    __tablename__ = 'auth_acl'

    id_ = Column(Integer, name='id', primary_key=True)
    value = Column(Text, nullable=False)
    token_uuid = Column(String(38), ForeignKey('auth_token.uuid', ondelete='CASCADE'), nullable=False)


class Token(Base):

    __tablename__ = 'auth_token'

    uuid = Column(String(38), server_default=text('uuid_generate_v4()'), primary_key=True)
    auth_id = Column(Text, nullable=False)
    user_uuid = Column(String(38))
    xivo_uuid = Column(String(38))
    issued_t = Column(Integer)
    expire_t = Column(Integer)
    acls = relationship('ACL')


class Policy(Base):

    __tablename__ = 'auth_policy'
    __table_args__ = (
        UniqueConstraint('name'),
    )

    uuid = Column(String(38), server_default=text('uuid_generate_v4()'), primary_key=True)
    name = Column(String(80), nullable=False)
    description = Column(Text)


class ACLTemplate(Base):

    __tablename__ = 'auth_acl_template'
    __table_args__ = (
        UniqueConstraint('template'),
    )

    id_ = Column(Integer, name='id', primary_key=True)
    template = Column(Text, nullable=False)


class ACLTemplatePolicy(Base):

    __tablename__ = 'auth_policy_template'

    policy_uuid = Column(String(38), ForeignKey('auth_policy.uuid', ondelete='CASCADE'), primary_key=True)
    template_id = Column(Integer, ForeignKey('auth_acl_template.id', ondelete='CASCADE'), primary_key=True)
