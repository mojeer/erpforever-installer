import io
import json
import os
import tarfile
import time

import pytest
from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from erpforever_installer.security import (
    b64, canonical, decrypt_release, normalize_site, recipient_id, safe_extract,
    validate_services, verify_license, verify_manifest,
)


@pytest.fixture
def signing():
    key = Ed25519PrivateKey.generate()
    public = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return key, public


@pytest.fixture
def claims():
    return {'format':1,'issuer':'ERPForever','id':'a'*32,'site':'erp.example.com',
            'secret':b64(os.urandom(32)),'expires':int(time.time())+3600}


def token(key, claims):
    raw=canonical(claims)
    return 'EF1.'+b64(raw)+'.'+b64(key.sign(raw))


def test_license_site_and_signature(signing, claims):
    key, public=signing
    value=token(key,claims)
    assert verify_license(value,public,'ERP.EXAMPLE.COM.')['site']=='erp.example.com'
    with pytest.raises(ValueError):verify_license(value,public,'another.example.com')
    with pytest.raises(ValueError):verify_license(value,public,now=claims['expires'])
    altered={**claims,'site':'another.example.com'}
    broken='EF1.'+b64(canonical(altered))+'.'+value.split('.')[-1]
    with pytest.raises(InvalidSignature):verify_license(broken,public)


@pytest.mark.parametrize('site',['https://erp.example.com','../etc','a..com','foo:123','a/b','-x.com','a-.com','x\n.com'])
def test_hostname_rejected(site):
    with pytest.raises(ValueError):normalize_site(site)


def package(signing, claims):
    import hashlib
    key,public=signing
    from erpforever_installer.security import unb64
    content=os.urandom(32);nonce=os.urandom(12);aad=b'ERPForever:0.1.0:1'
    encrypted=nonce+AESGCM(content).encrypt(nonce,b'test archive',aad)
    n=os.urandom(12);envelope=n+AESGCM(unb64(claims['secret'])).encrypt(n,content,aad)
    body={'format':1,'version':'0.1.0','sequence':1,'erpnext_image':'frappe/erpnext@sha256:'+'a'*64,
          'sha256':'sha256:'+hashlib.sha256(encrypted).hexdigest(),'recipients':{recipient_id(claims):b64(envelope)}}
    return {'manifest':body,'signature':b64(key.sign(canonical(body)))},encrypted,public


def test_release_decrypt_and_reject_tampering(signing,claims):
    doc,payload,public=package(signing,claims)
    assert decrypt_release(doc,payload,claims,public)==b'test archive'
    with pytest.raises(ValueError):decrypt_release(doc,payload+b'x',claims,public)
    doc['manifest']['sequence']=2
    with pytest.raises(InvalidSignature):verify_manifest(doc,public)


def test_another_customer_cannot_unwrap(signing,claims):
    doc,payload,public=package(signing,claims)
    with pytest.raises(InvalidTag):decrypt_release(doc,payload,{**claims,'secret':b64(os.urandom(32))},public)
    with pytest.raises(KeyError):decrypt_release(doc,payload,{**claims,'id':'b'*32},public)


@pytest.mark.parametrize('name,kind',[('../escape',None),('/etc/passwd',None),('link',tarfile.SYMTYPE),('link',tarfile.LNKTYPE),('device',tarfile.CHRTYPE)])
def test_malicious_archive_rejected(tmp_path,name,kind):
    buffer=io.BytesIO()
    with tarfile.open(fileobj=buffer,mode='w:gz') as tar:
        info=tarfile.TarInfo(name)
        if kind:info.type=kind;info.linkname='../../outside'
        tar.addfile(info,io.BytesIO(b''))
    with pytest.raises(ValueError):safe_extract(buffer.getvalue(),tmp_path/'release')
    assert not (tmp_path/'escape').exists()


def test_archive_extracts_only_under_destination(tmp_path):
    buffer=io.BytesIO()
    with tarfile.open(fileobj=buffer,mode='w:gz') as tar:
        info=tarfile.TarInfo('erpforever/__init__.py');info.size=3
        tar.addfile(info,io.BytesIO(b'abc'))
    safe_extract(buffer.getvalue(),tmp_path)
    assert (tmp_path/'erpforever/__init__.py').read_text()=='abc'


@pytest.mark.parametrize('spec',[
    {'image':'ubuntu:latest'},
    {'image':'x@sha256:'+'a'*64,'privileged':True},
    {'image':'x@sha256:'+'a'*64,'volumes':['/var/run/docker.sock:/socket']},
    {'image':'x@sha256:'+'a'*64,'network_mode':'host'},
    {'image':'x@sha256:'+'a'*64,'ports':['443:443']},
])
def test_unsafe_service_rejected(spec):
    with pytest.raises(ValueError):validate_services({'addon-test':spec})


def test_addon_named_volume_and_isolation(tmp_path):
    from erpforever_installer.deployment import config
    spec={'image':'ghcr.io/example/service@sha256:'+'a'*64,'volumes':['addon-data:/data']}
    validate_services({'addon-analytics':spec})
    config(tmp_path,'erp.example.com','0.1.0','frappe/erpnext@sha256:'+'a'*64,8797,{'addon-analytics':spec})
    doc=json.loads((tmp_path/'compose.yaml').read_text())
    assert doc['services']['addon-analytics']['security_opt']==['no-new-privileges:true']
    assert 'addon-data' in doc['volumes']
    assert all('ports' not in doc['services'][name] for name in ['db','redis-cache','redis-queue','backend','websocket'])


def test_release_replay_rejected(monkeypatch,signing,claims):
    from erpforever_installer import releases
    doc,_,public=package(signing,claims)
    monkeypatch.setattr(releases,'public_key',lambda:public)
    monkeypatch.setattr(releases,'fetch',lambda *_:json.dumps(doc).encode())
    with pytest.raises(ValueError):releases.load_release(token(signing[0],claims),'erp.example.com',minimum_sequence=2)
