import sys
sys.dont_write_bytecode = True
import importlib.util
import pathlib
import tempfile
import os
import base64
import hashlib
import unittest
from unittest.mock import patch
spec = importlib.util.spec_from_file_location('reader', pathlib.Path(__file__).with_name('asterisk_auth_reader.py'))
r = importlib.util.module_from_spec(spec)
spec.loader.exec_module(r)

class ReaderTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = pathlib.Path(self.tmp.name)
        self.cfg = self.root / 'logger.conf'
        self.cfg.write_text('[logfiles]\nsecurity => security\nmessages => notice,warning,error\n')
        self.log = self.root / 'security'
        self.log.write_bytes(b'first\nsecond\n')
    def read(self,c=None):
        return r.read(c or {},str(self.cfg),str(self.root))
    def cursor(self,b):
        data=base64.b64decode(b['data'])
        offset=b['offset']+len(data)
        return {b['source']:dict(identity=b['identity'],generation=b['generation'],offset=offset,anchor=hashlib.sha256(self.log.read_bytes()[max(0,offset-64):offset]).hexdigest(),gap=b['gap'],discard=False)}
    def test_continuation_restart_rotation(self):
        a=self.read();self.assertEqual(base64.b64decode(a['data']),b'first\nsecond\n')
        c=self.cursor(a);self.assertEqual(base64.b64decode(self.read(c)['data']),b'')
        with self.log.open('ab') as f:f.write(b'third\n')
        self.assertEqual(base64.b64decode(self.read(c)['data']),b'third\n')
        self.log.rename(self.root/'security.1');self.log.write_bytes(b'new\n')
        b=self.read(c);self.assertTrue(b['rotated']);self.assertEqual(base64.b64decode(b['data']),b'third\n')
        c['security']['offset']+=6;c['security']['anchor']=hashlib.sha256((self.root/'security.1').read_bytes()).hexdigest()
        b=self.read(c);self.assertEqual(base64.b64decode(b['data']),b'new\n');self.assertFalse(b['gap']);self.assertEqual(b['generation'],2)
    def test_truncate_and_missing_rotation(self):
        c=self.cursor(self.read());self.log.write_bytes(b'replaced-longer-than-original\n');b=self.read(c);self.assertTrue(b['gap']);self.assertEqual(b['offset'],0);self.assertEqual(b['generation'],2)
        self.log.unlink();self.log.write_bytes(b'new\n');b=self.read(c);self.assertTrue(b['gap'])
    def test_backlog_initial_tail(self):
        self.log.write_bytes(b'x\n'*(r.LIMIT*2));b=self.read();self.assertEqual(len(base64.b64decode(b['data'])),r.LIMIT);self.assertTrue(b['gap']);self.assertTrue(b['skip'])
        c={'security':dict(identity=b['identity'],generation=1,offset=0,anchor=hashlib.sha256(b'').hexdigest(),gap=False,discard=False)}
        b=self.read(c);self.assertEqual(b['offset'],0);self.assertGreater(b['size'],r.LIMIT)
    def test_fallback_missing_denied_and_symlink(self):
        self.log.unlink();self.assertEqual(self.read()['status'],'missing_source')
        (self.root/'messages').write_bytes(b'warning\n');self.assertEqual(self.read()['source'],'messages')
        with patch.object(r,'opened',side_effect=PermissionError()):self.assertEqual(self.read()['status'],'permission_denied')
        self.log.symlink_to(self.cfg);self.assertEqual(self.read()['source'],'messages')
        (self.root/'messages').unlink();self.assertEqual(self.read()['status'],'missing_source')
    def test_vicibox_console_and_milliseconds(self):
        self.cfg.write_text('[general]\ndateformat = %F %T.%3q\n[logfiles]\nconsole => notice,warning,error,dtmf\nmessages => notice,warning,error,debug,verbose,dtmf\nsecurity => security\n')
        b=self.read()
        self.assertEqual(b['source'],'security')
        self.assertFalse(b['configuration_incomplete'])
        self.assertTrue(b['warnings_supported'])
        self.log.unlink(); (self.root/'messages').write_bytes(b'warning\n')
        self.assertEqual(self.read()['source'],'messages')
    def test_fixed_sources_and_configuration(self):
        self.cfg.write_text('[logfiles]\n/arbitrary => security\n');self.assertEqual(self.read()['status'],'unsupported_configuration')
        self.cfg.write_text('#include arbitrary\n[logfiles]\n');self.assertEqual(self.read()['status'],'unsupported_configuration')
        with self.assertRaises(ValueError):self.read({'../../etc/shadow':{}})
        with self.assertRaises(ValueError):self.read({'security':{'offset':'0;evil'}})

if __name__=='__main__': unittest.main()
