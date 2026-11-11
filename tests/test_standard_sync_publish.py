import json
import subprocess
import sys
import unittest
import urllib.error
from urllib.parse import parse_qs,urlsplit
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import servers


class PublishSyncTest(unittest.TestCase):
    def test_sync_reports_success_skip_and_failure_without_hiding_errors(self):
        config={'coordinator':'us'}
        cases=[(0,{'configured':True,'verified':True,'updated':1},'verified'),
               (0,{'configured':False},'not_configured'),
               (1,{},'failed'),(0,{'configured':True,'verified':False},'failed')]
        with patch('fleet.ssh_args',return_value=['ssh','test']):
            for code,body,wanted in cases:
                with self.subTest(wanted=wanted),patch.object(servers.subprocess,'run',
                    return_value=subprocess.CompletedProcess([],code,json.dumps(body),'private details')):
                    self.assertEqual(servers.sync_standard_rules(config)['status'],wanted)

    def test_retired_country_routes_verify_active_urls_and_recover_on_mismatch(self):
        config={'coordinator':'us','subscription':{'public_url':'https://example.test/private?format=clash'},
                'servers':[{'country':'TW','status':'pending'},{'country':'JP'},{'country':'US'}]}
        calls=[]
        def run(args,**kwargs):
            action=args[-1].rsplit(' ',1)[-1];calls.append(action)
            body={'changed':True} if action=='retired-stage' else {'committed':True}
            return subprocess.CompletedProcess(args,0,json.dumps(body),'')
        class Response:
            status=200
            def __enter__(self):return self
            def __exit__(self,*args):pass
        def get(req,timeout):
            fmt=parse_qs(urlsplit(req.full_url).query)['format'][0]
            if fmt.endswith('-tw'):raise urllib.error.HTTPError(req.full_url,410,'retired',{},None)
            return Response()
        with patch('fleet.ssh_args',return_value=['ssh','test']),patch.object(servers.subprocess,'run',side_effect=run), \
             patch.object(servers.urllib.request,'urlopen',side_effect=get):
            self.assertEqual(servers.sync_retired_countries(config)['status'],'verified')
        self.assertEqual(calls,['retired-stage','retired-finish'])
        calls.clear()
        with patch('fleet.ssh_args',return_value=['ssh','test']),patch.object(servers.subprocess,'run',side_effect=run), \
             patch.object(servers.urllib.request,'urlopen',return_value=Response()),patch.object(servers.time,'sleep'):
            self.assertEqual(servers.sync_retired_countries(config)['status'],'failed')
        self.assertEqual(calls,['retired-stage','retired-recover'])


if __name__=='__main__':unittest.main()
