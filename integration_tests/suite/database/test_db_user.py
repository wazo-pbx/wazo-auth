# Copyright 2018-2021 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0-or-later

import os

from hamcrest import (
    assert_that,
    calling,
    contains,
    contains_inanyorder,
    empty,
    equal_to,
    has_entries,
    has_properties,
    none,
    not_,
)
from mock import ANY
from sqlalchemy import and_, func

from xivo_test_helpers.hamcrest.raises import raises
from xivo_test_helpers.mock import ANY_UUID
from wazo_auth import exceptions
from wazo_auth.database import models
from xivo_test_helpers.hamcrest.uuid_ import uuid_

from ..helpers import fixtures, base
from ..helpers.constants import UNKNOWN_UUID

USER_UUID = '00000000-0000-4000-9000-111111111111'


class TestUserDAO(base.DAOTestCase):

    salt = os.urandom(64)

    @staticmethod
    def _email(address, main=False, confirmed=None):
        email = {'address': address, 'main': main}
        if confirmed is not None:
            email['confirmed'] = confirmed
        return email

    @fixtures.db.user(email_address='foobar@example.com', email_confirmed=False)
    def test_user_email_association(self, user_uuid):
        emails = []

        assert_that(
            calling(self._user_dao.update_emails).with_args(UNKNOWN_UUID, emails),
            raises(exceptions.UnknownUserException),
        )

        result = self._user_dao.update_emails(user_uuid, emails)
        assert_that(result, empty())
        assert_that(self._user_dao.get_emails(user_uuid), equal_to(result))
        assert_that(self._email_exists('foobar@example.com'), equal_to(False))

        emails = [self._email('foobar@example.com', main=True, confirmed=False)]
        result = self._user_dao.update_emails(user_uuid, emails)
        assert_that(result, contains(*[has_entries(**email) for email in emails]))
        assert_that(self._user_dao.get_emails(user_uuid), contains_inanyorder(*result))

        emails = [
            self._email('foobar@example.com'),
            self._email('foobaz@example.com', main=True, confirmed=True),
        ]
        result = self._user_dao.update_emails(user_uuid, emails)
        assert_that(
            result,
            contains_inanyorder(
                # foobar "lost"" main and stayed unconfirmed
                has_entries(address='foobar@example.com', main=False, confirmed=False),
                has_entries(address='foobaz@example.com', main=True, confirmed=True),
            ),
        )
        assert_that(self._user_dao.get_emails(user_uuid), contains_inanyorder(*result))

        emails = [
            self._email('foobar@example.com', main=False, confirmed=True),
            self._email('foobaz@example.com', main=True),
        ]
        result = self._user_dao.update_emails(user_uuid, emails)
        assert_that(
            result,
            contains_inanyorder(
                has_entries(address='foobar@example.com', main=False, confirmed=True),
                # confirmed does not change if unspecified for an existing address
                has_entries(address='foobaz@example.com', main=True, confirmed=True),
            ),
        )
        assert_that(self._user_dao.get_emails(user_uuid), contains_inanyorder(*result))

        emails = [
            self._email('bazinga@example.com', main=True),  # <-- new address
            self._email('foobaz@example.com', main=False),
        ]
        result = self._user_dao.update_emails(user_uuid, emails)
        assert_that(
            result,
            contains_inanyorder(
                # confirmed is false when unspecified and inexistant
                has_entries(address='bazinga@example.com', main=True, confirmed=False),
                has_entries(address='foobaz@example.com', main=False, confirmed=True),
            ),
        )
        assert_that(self._user_dao.get_emails(user_uuid), contains_inanyorder(*result))

        emails = [
            {'address': 'bazinga@example.com', 'main': True, 'confirmed': None},
            {'address': 'foobaz@example.com', 'main': False, 'confirmed': None},
        ]
        result = self._user_dao.update_emails(user_uuid, emails)
        assert_that(
            result,
            contains_inanyorder(
                has_entries(address='bazinga@example.com', main=True, confirmed=False),
                has_entries(address='foobaz@example.com', main=False, confirmed=True),
            ),
        )
        assert_that(self._user_dao.get_emails(user_uuid), contains_inanyorder(*result))

    @fixtures.db.policy()
    @fixtures.db.user()
    def test_user_policy_association(self, user_uuid, policy_uuid):
        self._user_dao.add_policy(user_uuid, policy_uuid)
        count = (
            self.session.query(func.count(models.UserPolicy.user_uuid))
            .filter(
                and_(
                    models.UserPolicy.user_uuid == user_uuid,
                    models.UserPolicy.policy_uuid == policy_uuid,
                )
            )
            .scalar()
        )

        assert_that(count, equal_to(1))

        assert_that(
            calling(self._user_dao.add_policy).with_args(user_uuid, policy_uuid),
            not_(raises(Exception)),
            'associating twice should not fail',
        )

        assert_that(
            calling(self._user_dao.add_policy).with_args('unknown', policy_uuid),
            raises(exceptions.UnknownUserException),
            'unknown user',
        )

        assert_that(
            calling(self._user_dao.add_policy).with_args(user_uuid, 'unknown'),
            raises(exceptions.UnknownPolicyException),
            'unknown policy',
        )

    @fixtures.db.policy()
    @fixtures.db.user()
    def test_user_remove_policy(self, user_uuid, policy_uuid):
        nb_deleted = self._user_dao.remove_policy(user_uuid, policy_uuid)
        assert_that(nb_deleted, equal_to(0))

        self._user_dao.add_policy(user_uuid, policy_uuid)

        nb_deleted = self._user_dao.remove_policy(self.unknown_uuid, policy_uuid)
        assert_that(nb_deleted, equal_to(0))

        nb_deleted = self._user_dao.remove_policy(user_uuid, self.unknown_uuid)
        assert_that(nb_deleted, equal_to(0))

        nb_deleted = self._user_dao.remove_policy(user_uuid, policy_uuid)
        assert_that(nb_deleted, equal_to(1))

    @fixtures.db.policy(name='c', description='The third foobar')
    @fixtures.db.policy(name='b', description='The second foobar')
    @fixtures.db.policy(name='a')
    @fixtures.db.user()
    def test_user_count_policies(self, user_uuid, policy_a, policy_b, policy_c):
        result = self._user_dao.count_policies(user_uuid)
        assert_that(result, equal_to(0), 'none associated')

        self._user_dao.add_policy(user_uuid, policy_a)
        self._user_dao.add_policy(user_uuid, policy_b)
        self._user_dao.add_policy(user_uuid, policy_c)

        result = self._user_dao.count_policies(user_uuid)
        assert_that(result, equal_to(3), 'no filter')

        result = self._user_dao.count_policies(user_uuid, name='a')
        assert_that(result, equal_to(1), 'strict match')

        result = self._user_dao.count_policies(user_uuid, name='a', filtered=False)
        assert_that(result, equal_to(3), 'strict not filtered')

        result = self._user_dao.count_policies(user_uuid, search='foobar')
        assert_that(result, equal_to(2), 'search')

        result = self._user_dao.count_policies(
            user_uuid, search='foobar', filtered=False
        )
        assert_that(result, equal_to(3), 'search not filtered')

    @fixtures.db.user(uuid=USER_UUID)
    @fixtures.db.token(auth_id=USER_UUID)
    @fixtures.db.token(auth_id=USER_UUID)
    def test_user_count_sessions(self, *_):
        result = self._user_dao.count_sessions(UNKNOWN_UUID)
        assert_that(result, equal_to(0), 'none associated')

        result = self._user_dao.count_sessions(USER_UUID)
        assert_that(result, equal_to(2), 'no filter')

    def test_user_creation(self):
        username = 'foobar'
        hash_ = 'the_hashed_password'
        email_address = 'foobar@example.com'

        user_uuid = self._user_dao.create(
            username,
            email_address=email_address,
            tenant_uuid=self.top_tenant_uuid,
            hash_=hash_,
            salt=self.salt,
            purpose='user',
        )['uuid']

        assert_that(user_uuid, equal_to(ANY_UUID))
        result = self._user_dao.list_(uuid=user_uuid)
        assert_that(
            result,
            contains(
                has_entries(
                    username=username,
                    emails=contains(
                        has_entries(address=email_address, confirmed=False, main=True)
                    ),
                )
            ),
        )
        assert_that(
            calling(self._user_dao.create).with_args(
                'foo',
                uuid=user_uuid,
                email_address='foo@bar.baz',
                tenant_uuid=self.top_tenant_uuid,
                hash_='',
                salt=b'',
                purpose='user',
            ),
            raises(
                exceptions.ConflictException,
                has_properties(
                    status_code=409, resource='users', details=has_entries(uuid=ANY)
                ),
            ),
        )

    def test_user_creation_email_confirmed(self):
        username = 'foobar'
        hash_ = 'the_hashed_password'
        email_address = 'foobar@example.com'

        user_uuid = self._user_dao.create(
            username,
            email_address=email_address,
            tenant_uuid=self.top_tenant_uuid,
            hash_=hash_,
            salt=self.salt,
            purpose='user',
            email_confirmed=True,
        )['uuid']

        try:
            result = self._user_dao.list_(uuid=user_uuid)
            assert_that(
                result,
                contains(
                    has_entries(
                        username=username,
                        emails=contains(
                            has_entries(
                                uuid=uuid_(), address=email_address, confirmed=True
                            )
                        ),
                    )
                ),
            )
        finally:
            self._user_dao.delete(user_uuid)

    @fixtures.db.user(username='foobar')
    def test_that_the_username_is_unique(self, user_uuid):
        assert_that(
            calling(self._user_dao.create).with_args(
                'foobar',
                email_address='foo@bar',
                hash_='hash_two',
                salt=self.salt,
                purpose='user',
                tenant_uuid=self.top_tenant_uuid,
            ),
            raises(
                exceptions.ConflictException,
                has_properties(
                    status_code=409, resource='users', details=has_entries(username=ANY)
                ),
            ),
        )

    @fixtures.db.user(email_address='foobar@example.com')
    def test_that_the_email_is_unique(self, user_uuid):
        assert_that(
            calling(self._user_dao.create).with_args(
                'bar',
                email_address='foobar@example.com',
                tenant_uuid=self.top_tenant_uuid,
                hash_='hash_two',
                salt=self.salt,
                purpose='user',
            ),
            raises(
                exceptions.ConflictException,
                has_properties(
                    status_code=409,
                    resource='users',
                    details=has_entries(email_address=ANY),
                ),
            ),
        )

    @fixtures.db.user()
    @fixtures.db.user()
    @fixtures.db.user()
    def test_user_count_no_search_term_no_strict_filter(self, a, b, c):
        result = self._user_dao.count()
        assert_that(result, equal_to(3))

    @fixtures.db.user(username='foo')
    @fixtures.db.user(email_address='foobar@example.com')
    @fixtures.db.user(username='bar', email_address='bar@example.com')
    def test_user_count_no_search_term_strict_filter(self, a, b, c):
        result = self._user_dao.count(username='foo')
        assert_that(result, equal_to(1))

        result = self._user_dao.count(email_address='foobar@example.com')
        assert_that(result, equal_to(1))

        result = self._user_dao.count(uuid=c)
        assert_that(result, equal_to(1))

    @fixtures.db.user(username='foo123')
    @fixtures.db.user(email_address='foobar123@example.com')
    @fixtures.db.user(username='bar456', email_address='bar456@example.com')
    def test_user_count_search_term(self, a, b, c):
        result = self._user_dao.count(search='123')
        assert_that(result, equal_to(2))

    @fixtures.db.user(username='foo')
    @fixtures.db.user(email_address='foobar@example.com')
    @fixtures.db.user(username='bar', email_address='bar@example.com')
    def test_user_count_mixed_strict_and_search(self, a, b, c):
        result = self._user_dao.count(search='foo', uuid=a)
        assert_that(result, equal_to(0))

    @fixtures.db.user(username='foo')
    @fixtures.db.user(email_address='foobar@example.com')
    @fixtures.db.user(username='bar', email_address='bar@example.com')
    def test_user_count_unfiltered(self, a, b, c):
        result = self._user_dao.count(search='foo', filtered=False)
        assert_that(result, equal_to(3))

        result = self._user_dao.count(uuid=a, filtered=False)
        assert_that(result, equal_to(3))

    @fixtures.db.user(username='a', email_address='a@example.com')
    @fixtures.db.user(username='b', email_address='b@example.com')
    @fixtures.db.user(username='c', email_address='c@example.com')
    def test_user_list_no_search_term_no_strict_filter(self, c, b, a):
        result = self._user_dao.list_()

        assert_that(
            result,
            contains_inanyorder(
                has_entries(
                    uuid=a,
                    username='a',
                    tenant_uuid=self.top_tenant_uuid,
                    emails=contains_inanyorder(
                        has_entries(address='a@example.com', main=True, confirmed=False)
                    ),
                ),
                has_entries(
                    uuid=b,
                    username='b',
                    tenant_uuid=self.top_tenant_uuid,
                    emails=contains_inanyorder(
                        has_entries(address='b@example.com', main=True, confirmed=False)
                    ),
                ),
                has_entries(
                    uuid=c,
                    username='c',
                    tenant_uuid=self.top_tenant_uuid,
                    emails=contains_inanyorder(
                        has_entries(address='c@example.com', main=True, confirmed=False)
                    ),
                ),
            ),
        )

    @fixtures.db.user(
        firstname='foo', lastname='foo', username='foo', email_address='foo@example.com'
    )
    @fixtures.db.user(
        firstname='bar', lastname='bar', username='bar', email_address='bar@example.com'
    )
    @fixtures.db.user(
        firstname='baz', lastname='baz', username='baz', email_address='baz@example.com'
    )
    def test_user_list_with_search_term(self, baz, bar, foo):
        result = self._user_dao.list_(search='@example.')

        assert_that(
            result,
            contains_inanyorder(
                has_entries(
                    uuid=foo,
                    username='foo',
                    tenant_uuid=self.top_tenant_uuid,
                    emails=contains_inanyorder(
                        has_entries(
                            address='foo@example.com', main=True, confirmed=False
                        )
                    ),
                ),
                has_entries(
                    uuid=bar,
                    username='bar',
                    tenant_uuid=self.top_tenant_uuid,
                    emails=contains_inanyorder(
                        has_entries(
                            address='bar@example.com', main=True, confirmed=False
                        )
                    ),
                ),
                has_entries(
                    uuid=baz,
                    username='baz',
                    tenant_uuid=self.top_tenant_uuid,
                    emails=contains_inanyorder(
                        has_entries(
                            address='baz@example.com', main=True, confirmed=False
                        )
                    ),
                ),
            ),
        )

        result = self._user_dao.list_(search='foo')
        assert_that(
            result,
            contains_inanyorder(
                has_entries(
                    uuid=foo,
                    username='foo',
                    emails=contains_inanyorder(
                        has_entries(
                            address='foo@example.com', main=True, confirmed=False
                        )
                    ),
                )
            ),
        )

    @fixtures.db.user(
        firstname='foo', lastname='foo', username='foo', email_address='foo@example.com'
    )
    @fixtures.db.user(
        firstname='bar', lastname='bar', username='bar', email_address='bar@example.com'
    )
    @fixtures.db.user(
        firstname='baz', lastname='baz', username='baz', email_address='baz@example.com'
    )
    def test_user_list_with_strict_filters(self, baz, bar, foo):
        result = self._user_dao.list_(username='foo')

        assert_that(
            result,
            contains_inanyorder(
                has_entries(
                    uuid=foo,
                    username='foo',
                    emails=contains_inanyorder(
                        has_entries(
                            address='foo@example.com', main=True, confirmed=False
                        )
                    ),
                )
            ),
        )

        result = self._user_dao.list_(uuid=foo)
        assert_that(
            result,
            contains_inanyorder(
                has_entries(
                    uuid=foo,
                    username='foo',
                    emails=contains_inanyorder(
                        has_entries(
                            address='foo@example.com', main=True, confirmed=False
                        )
                    ),
                )
            ),
        )

    @fixtures.db.user(
        firstname='foo', lastname='foo', username='foo', email_address='foo@example.com'
    )
    @fixtures.db.user(
        firstname='bar', lastname='bar', username='bar', email_address='bar@example.com'
    )
    @fixtures.db.user(
        firstname='baz', lastname='baz', username='baz', email_address='baz@example.com'
    )
    def test_user_list_with_strict_filters_and_search(self, baz, bar, foo):
        result = self._user_dao.list_(username='foo', search='baz')
        assert_that(result, empty())

        result = self._user_dao.list_(uuid=foo, search='example')
        assert_that(
            result,
            contains_inanyorder(
                has_entries(
                    uuid=foo,
                    username='foo',
                    emails=contains_inanyorder(
                        has_entries(
                            address='foo@example.com', main=True, confirmed=False
                        )
                    ),
                )
            ),
        )

    @fixtures.db.user(username='a')
    @fixtures.db.user(username='b')
    @fixtures.db.user(username='c')
    @fixtures.db.user(username='d')
    @fixtures.db.user(username='e')
    @fixtures.db.user(username='f')
    @fixtures.db.user(username='g')
    @fixtures.db.user(username='h')
    @fixtures.db.user(username='i')
    def test_pagination(self, i, h, g, f, e, d, c, b, a):
        result = self._user_dao.list_(
            order='username', direction='desc', limit=1, offset=0
        )
        assert_that(result, contains_inanyorder(has_entries(uuid=i)))

        result = self._user_dao.list_(
            order='username', direction='asc', limit=2, offset=1
        )
        assert_that(
            result, contains_inanyorder(has_entries(uuid=b), has_entries(uuid=c))
        )

        result = self._user_dao.list_(
            order='username', direction='asc', limit=2, offset=1
        )
        assert_that(
            result, contains_inanyorder(has_entries(uuid=b), has_entries(uuid=c))
        )

    @fixtures.db.user(username='a', firstname='a', lastname='a')
    @fixtures.db.user(username='b', firstname='b', lastname='b')
    def test_sort(self, b, a):
        self._check_sort('username', a, b)
        self._check_sort('firstname', a, b)
        self._check_sort('lastname', a, b)

    def _check_sort(self, column, a, b):
        result = self._user_dao.list_(order=column, direction='asc')
        assert_that(result, contains(has_entries(uuid=a), has_entries(uuid=b)))

        result = self._user_dao.list_(order=column, direction='desc')
        assert_that(result, contains(has_entries(uuid=b), has_entries(uuid=a)))

    @fixtures.db.user(email_address='foo@example.com')
    def test_delete(self, user_uuid):
        self._user_dao.delete(user_uuid)

        assert_that(
            calling(self._user_dao.delete).with_args(user_uuid),
            raises(exceptions.UnknownUserException),
        )

        assert_that(self._email_exists('foobar@example.com'), equal_to(False))

    @fixtures.db.user(uuid=USER_UUID)
    @fixtures.db.user_external_auth(user_uuid=USER_UUID)
    def test_delete_external_auth(self, _, user_uuid):
        user_external_auth = (
            self.session.query(models.UserExternalAuth)
            .filter(models.UserExternalAuth.user_uuid == user_uuid)
            .first()
        )
        type_uuid = user_external_auth.external_auth_type_uuid

        self._user_dao.delete(user_uuid)

        self.session.expire_all()
        result = self.session.query(models.UserExternalAuth).get((user_uuid, type_uuid))
        assert_that(result, equal_to(None))

    @fixtures.db.user(username='foobar')
    @fixtures.db.user(username='foobaz', enabled=False)
    def test_get_credential(self, *ignored_uuids):
        assert_that(
            calling(self._user_dao.get_credentials).with_args('not-foobar'),
            raises(exceptions.UnknownUsernameException),
        )

        assert_that(
            calling(self._user_dao.get_credentials).with_args('foobaz'),
            raises(exceptions.UnknownUsernameException),
        )

        hash_, salt = self._user_dao.get_credentials('foobar')
        assert_that(hash_, not_(none()))
        assert_that(salt, not_(none()))

    # fmt: off
    @fixtures.db.user(username='u1', email_address=None)
    @fixtures.db.user(username='u2', email_address='u2@example.com', email_confirmed=True)
    @fixtures.db.user(username='u3', email_address='u3@example.com', email_confirmed=False)
    # fmt: on
    def test_get_username_by_login(self, u3, u2, u1):
        result = self._user_dao.get_username_by_login('u1')
        assert_that(result, equal_to('u1'))

        result = self._user_dao.get_username_by_login('u2@example.com')
        assert_that(result, equal_to('u2'))

        assert_that(
            calling(self._user_dao.get_username_by_login).with_args('u3@example.com'),
            raises(exceptions.UnknownLoginException),
        )

        assert_that(
            calling(self._user_dao.get_username_by_login).with_args('u0'),
            raises(exceptions.UnknownLoginException),
        )

    def _email_exists(self, address):
        filter_ = models.Email.address == address
        return (
            self.session.query(func.count(models.Email.uuid)).filter(filter_).scalar()
            > 0
        )
