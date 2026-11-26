import secrets
import sqlite3
import time
from dataclasses import asdict

import jwt
import pytest

from backend.security.auth.sessions import SessionStore, ISSUER, AUDIENCE
from backend.security.auth.users import UserStore

PASSWORD = 'fictional test password only'

@pytest.fixture
def store(tmp_path):
    users = UserStore(tmp_path / 'test.db')
    users.initialize()
    users.seed_demo_users({'alice': PASSWORD, 'bob': PASSWORD})
    sessions = SessionStore(users, signing_key=secrets.token_hex(32))
    sessions.initialize()
    return sessions

@pytest.mark.parametrize('name,role', [('alice','intern'),('bob','manager')])
def test_login(store,name,role):
    token = store.login(name,PASSWORD)
    session = store.validate(token)
    assert session.user.role == role
    assert 'password_hash' not in asdict(session.user)
    assert 'role' not in jwt.decode(token, options={'verify_signature':False})

def test_wrong_password(store):
    assert store.login('alice','incorrect') is None
    with sqlite3.connect(store.users.path) as conn:
        assert conn.execute('SELECT count(*) FROM sessions').fetchone()[0] == 0

@pytest.mark.parametrize('token',[None,'', 'bad', 1, 'x'*4097])
def test_invalid(store,token):
    assert store.validate(token) is None
    assert not store.logout(token)

def test_persistence_and_logout(store):
    token = store.login('alice',PASSWORD)
    other = store.login('alice',PASSWORD)
    reopened = SessionStore(store.users,signing_key=store._key)
    reopened.initialize()
    assert reopened.validate(token)
    assert reopened.logout(token)
    assert not store.validate(token)
    assert not store.logout(token)
    assert store.validate(other)

def test_wrong_key(store):
    token = store.login('alice',PASSWORD)
    other = SessionStore(store.users,signing_key=secrets.token_hex(32))
    assert other.validate(token) is None

@pytest.mark.parametrize('change',[{'jti':'0'*64},{'sub':'2'},{'exp':1},{'iss':'other'},{'aud':'other'},{'iat':2**62},{'exp':2**64},{'sub':'9'*100},{'iat':'1'}])
def test_signed_but_invalid(store,change):
    token = store.login('alice',PASSWORD)
    claims = jwt.decode(token,options={'verify_signature':False})
    claims.update(change)
    forged = jwt.encode(claims,store._key,algorithm='HS256')
    assert store.validate(forged) is None
    assert not store.logout(forged)
    assert store.validate(token)

def test_unsigned(store):
    token = store.login('alice',PASSWORD)
    claims = jwt.decode(token,options={'verify_signature':False})
    assert store.validate(jwt.encode(claims,'',algorithm='none')) is None

def test_disabled_user(store):
    token = store.login('alice',PASSWORD)
    with sqlite3.connect(store.users.path) as conn:
        conn.execute("UPDATE users SET is_active=0 WHERE username='alice'")
    assert store.validate(token) is None
    assert store.login('alice',PASSWORD) is None

def test_expiry(store,monkeypatch):
    token = store.login('alice',PASSWORD)
    import jwt.api_jwt
    from datetime import datetime, timezone, timedelta
    class Future(datetime):
        @classmethod
        def now(cls,tz=None):
            return datetime.now(timezone.utc)+timedelta(hours=25)
    monkeypatch.setattr(jwt.api_jwt,'datetime',Future)
    assert store.validate(token) is None
    assert not store.logout(token)

def test_missing_secret(store,monkeypatch):
    monkeypatch.delenv('AGENTGUARD_JWT_SECRET',raising=False)
    with pytest.raises(ValueError):
        SessionStore(store.users)

def test_signature_tampering(store):
    token = store.login('alice',PASSWORD)
    head, payload, signature = token.split('.')
    changed = ('A' if signature[0] != 'A' else 'B') + signature[1:]
    assert store.validate('.'.join((head,payload,changed))) is None
    assert store.validate(token)


def test_server_expiry(store,monkeypatch):
    token = store.login('alice',PASSWORD)
    import backend.security.auth.sessions as module
    future = int(time.time()) + store.ttl + 1
    monkeypatch.setattr(module.time,'time',lambda: future)
    assert store.validate(token) is None
    assert not store.logout(token)


def test_role_comes_from_database(store):
    token = store.login('alice',PASSWORD)
    claims = jwt.decode(token,options={'verify_signature':False})
    claims['role'] = 'manager'
    assert store.validate(jwt.encode(claims,store._key,algorithm='HS256')).user.role == 'intern'


def test_no_raw_token_stored(store):
    token = store.login('alice',PASSWORD)
    assert token.encode() not in store.users.path.read_bytes()


@pytest.mark.parametrize('algorithm', ['HS384', 'HS512'])
def test_disallowed_signed_algorithm(store, algorithm):
    token = store.login('alice', PASSWORD)
    claims = jwt.decode(token, options={'verify_signature': False})
    forged = jwt.encode(claims, store._key, algorithm=algorithm)
    assert store.validate(forged) is None
    assert not store.logout(forged)
    assert store.validate(token) is not None


@pytest.mark.parametrize('claim', ['iss', 'aud', 'sub', 'jti', 'iat', 'exp'])
def test_missing_required_claim(store, claim):
    token = store.login('alice', PASSWORD)
    claims = jwt.decode(token, options={'verify_signature': False})
    del claims[claim]
    forged = jwt.encode(claims, store._key, algorithm='HS256')
    assert store.validate(forged) is None
    assert not store.logout(forged)
    assert store.validate(token) is not None
