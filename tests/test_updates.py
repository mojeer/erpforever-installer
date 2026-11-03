import io
import json
from pathlib import Path
import subprocess
import tarfile

import pytest

from erpforever_installer import agent, deployment


@pytest.fixture
def prepared(tmp_path,monkeypatch):
    (tmp_path/'app').mkdir()
    (tmp_path/'app/old.txt').write_text('old source')
    for name in ['compose.yaml','Dockerfile']:(tmp_path/name).write_text('old '+name)
    (tmp_path/'deployment.json').write_text(json.dumps({'site':'erp.example.com','version':'0.1.0','sequence':1,
                                                       'image':'old-image','automatic':True}))
    (tmp_path/'license.token').write_text('opaque test token')
    manifest={'version':'0.1.1','sequence':2,'erpnext_image':'frappe/erpnext@sha256:'+'a'*64}
    monkeypatch.setattr(agent,'load_release',lambda *_:({'manifest':manifest},{},'https://example.invalid/verified'))
    monkeypatch.setattr(agent,'public_key',lambda:b'x'*32)
    monkeypatch.setattr(agent,'fetch_payload',lambda _:b'ciphertext')
    buffer=io.BytesIO()
    with tarfile.open(fileobj=buffer,mode='w:gz') as tar:
        info=tarfile.TarInfo('new.txt');info.size=10;tar.addfile(info,io.BytesIO(b'new source'))
    monkeypatch.setattr(agent,'decrypt_release',lambda *_:buffer.getvalue())
    updater=agent.Updater(tmp_path)
    calls=[]
    updater.command=lambda *args:calls.append(args)
    updater.healthcheck=lambda _:None
    return updater,calls,tmp_path


def test_update_backs_up_before_migrating(prepared):
    updater,calls,root=prepared
    updater._apply()
    backup=next(i for i,c in enumerate(calls) if 'backup' in c)
    migration=next(i for i,c in enumerate(calls) if 'migrate' in c)
    resume=next(i for i,c in enumerate(calls) if c[-2:]==('set-maintenance-mode','off'))
    assert backup<migration<resume
    assert '--with-files' in calls[backup]
    assert json.loads((root/'deployment.json').read_text())['sequence']==2
    assert (root/'app/new.txt').read_text()=='new source'
    assert (root/'previous-app/old.txt').exists()
    assert updater.state['running'] is False


def test_backup_failure_never_replaces_code_or_migrates(prepared):
    updater,calls,root=prepared
    def command(*args):
        calls.append(args)
        if 'backup' in args:raise subprocess.CalledProcessError(1,'backup')
    updater.command=command
    updater._apply()
    assert (root/'app/old.txt').exists()
    assert not any('migrate' in c for c in calls)
    assert any(c[-2:]==('set-maintenance-mode','off') for c in calls)
    assert json.loads((root/'deployment.json').read_text())['sequence']==1


def test_build_failure_restores_previous_source_and_config(prepared):
    updater,calls,root=prepared
    def command(*args):
        calls.append(args)
        if args[0]=='build':raise subprocess.CalledProcessError(1,'build')
    updater.command=command
    updater._apply()
    assert (root/'app/old.txt').exists()
    assert (root/'Dockerfile').read_text()=='old Dockerfile'
    assert not any('migrate' in c for c in calls)
    assert not updater.state.get('recovery_required')


def test_migration_failure_keeps_maintenance_for_owner_recovery(prepared):
    updater,calls,root=prepared
    def command(*args):
        calls.append(args)
        if 'migrate' in args:raise subprocess.CalledProcessError(1,'migrate')
    updater.command=command
    updater._apply()
    assert updater.state['recovery_required'] is True
    assert not any(c[-2:]==('set-maintenance-mode','off') for c in calls)
    assert json.loads((root/'deployment.json').read_text())['sequence']==1
    assert (root/'previous-app/old.txt').exists()


def test_tampered_download_never_touches_runtime(prepared,monkeypatch):
    updater,calls,root=prepared
    def reject(*_):raise ValueError('bad signature')
    monkeypatch.setattr(agent,'load_release',reject)
    updater._apply()
    assert calls==[]
    assert (root/'app/old.txt').exists()


def test_private_write_atomic_and_permissions(tmp_path):
    path=tmp_path/'secret'
    deployment.private_write(path,'first')
    deployment.private_write(path,'second')
    assert path.read_text()=='second'
    assert path.stat().st_mode&0o777==0o600
    assert list(tmp_path.iterdir())==[path]
    link=tmp_path/'link';link.symlink_to(path)
    with pytest.raises(ValueError):deployment.private_write(link,'bad')
    assert path.read_text()=='second'


def test_recovery_blocks_automatic_queueing(prepared):
    updater,_,_=prepared
    updater.state['recovery_required']=True
    assert updater.submit()['recovery_required'] is True
    assert not updater.state.get('running')
