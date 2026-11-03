import io
import tarfile

import pytest

from erpforever_installer import agent


def test_agent_replaced_atomically_before_application_update(tmp_path,monkeypatch):
    import json
    (tmp_path/'deployment.json').write_text(json.dumps({'site':'erp.example.com','version':'0.1.0','sequence':1}))
    (tmp_path/'license.token').write_text('test')
    (tmp_path/'agent-version').write_text('0.1.0')
    old=tmp_path/'control/agents/0.1.0/erpforever_installer'
    old.mkdir(parents=True)
    (old/'agent.py').write_text('old code')
    link=tmp_path/'control/erpforever_installer'
    link.symlink_to('agents/0.1.0/erpforever_installer',target_is_directory=True)
    buffer=io.BytesIO()
    with tarfile.open(fileobj=buffer,mode='w:gz') as tar:
        for name,value in [('agent.py',b'new signed code'),('public-key.hex',(b'x'*32).hex().encode())]:
            info=tarfile.TarInfo('deployment/erpforever_installer/'+name);info.size=len(value)
            tar.addfile(info,io.BytesIO(value))
    monkeypatch.setattr(agent,'load_release',lambda *_:({'manifest':{'version':'0.1.1','sequence':2}}, {},'url'))
    monkeypatch.setattr(agent,'fetch_payload',lambda _:b'encrypted')
    monkeypatch.setattr(agent,'decrypt_release',lambda *_:buffer.getvalue())
    monkeypatch.setattr(agent,'public_key',lambda:b'x'*32)
    def restart(_):raise SystemExit(1)
    monkeypatch.setattr(agent.os,'_exit',restart)
    updater=agent.Updater(tmp_path)
    calls=[];updater.command=lambda *args:calls.append(args)
    with pytest.raises(SystemExit):updater._apply()
    assert link.is_symlink()
    assert (link/'agent.py').read_text()=='new signed code'
    assert (old/'agent.py').read_text()=='old code'
    assert (tmp_path/'agent-version').read_text()=='0.1.1'
    assert updater.state['running'] is False
    assert calls==[]
