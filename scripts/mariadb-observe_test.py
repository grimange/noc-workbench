"""Deterministic fixed-reader protocol, bounds and subprocess cleanup proofs."""
import importlib.machinery, pathlib, subprocess, sys, time, unittest
from unittest import mock
reader = importlib.machinery.SourceFileLoader('reader', str(pathlib.Path(__file__).with_name('mariadb-observe'))).load_module()
class ReaderTests(unittest.TestCase):
    def test_nullable_metrics_and_separate_replication_permission(self):
        replies = [[dict(probe='1', version='10.11.15-MariaDB', identity='db.example.invalid', server_id='1')],
                   [dict(Variable_name='Threads_running',Value='NULL'),dict(Variable_name='Connections',Value='12')],
                   [dict(capacity='200')]]
        calls=[]
        def query(sql,socket,deadline):
            calls.append(sql)
            if replies:return replies.pop(0)
            raise reader.Failure('permission_denied')
        with mock.patch.object(reader,'query',side_effect=query): got=reader.collect('/run/test.sock')
        self.assertEqual(got['status'],'ready');self.assertNotIn('Threads_running',got['metrics'])
        self.assertEqual(got['metrics']['Connections'],12);self.assertEqual(got['replication'],'permission_denied')
        self.assertIn('SHOW GLOBAL STATUS',calls[1]);self.assertEqual(calls[3],'SHOW ALL REPLICAS STATUS;\n')
        self.assertFalse(any('PROCESSLIST' in q or 'asterisk.' in q for q in calls))
    def test_activity_failure_preserves_successful_probe(self):
        head=dict(probe='1',version='10.11.15-MariaDB',identity='db.example.invalid',server_id='1')
        for replies in ([ [head],reader.Failure('permission_denied'),[] ], [[head],[dict(Variable_name='Connections',Value='12')],reader.Failure('timeout'),[]]):
            with mock.patch.object(reader,'query',side_effect=replies):got=reader.collect('/run/test.sock')
            self.assertEqual(got['status'],'ready');self.assertEqual(got['version'],head['version'])
            self.assertEqual(got['replication'],'ready');self.assertIn(got['activity_status'],('permission_denied','timeout'))
            if got['activity_status']=='timeout':self.assertEqual(got['metrics']['Connections'],12)
    def test_multiple_named_channels_and_null_lag(self):
        head=dict(probe='1',version='10.11.15-MariaDB',identity='db.example.invalid',server_id='1')
        c=dict(Connection_name='west',Master_Host='192.0.2.5',Master_Port='3306',Slave_IO_Running='Yes',Slave_SQL_Running='No',Seconds_Behind_Master='NULL',Last_IO_Errno='0',Last_SQL_Errno='1062',Last_SQL_Error='secret SQL discarded',Master_Password='secret discarded')
        with mock.patch.object(reader,'query',side_effect=[[head],[],[dict(capacity='200')],[c,dict(c,Connection_name='east')]]):got=reader.collect('/run/test.sock')
        self.assertEqual(len(got['channels']),2);self.assertIsNone(got['channels'][0]['lag'])
        self.assertNotIn('secret',str(got));self.assertEqual(got['channels'][0]['sql_error'],1062)
    def test_failure_classification_no_server_diagnostics(self):
        for code in ('authentication_denied','connection_unavailable','timeout','permission_denied'):
            with mock.patch.object(reader,'query',side_effect=reader.Failure(code)):got=reader.collect('/run/test.sock')
            self.assertEqual(got['status'],code);self.assertEqual(got['metrics'],{})
    def child_query(self,code,timeout=False):
        original=subprocess.Popen;children=[]
        def popen(argv,**kwargs):
            self.assertEqual(argv[0],'/usr/bin/mariadb');self.assertIn('--no-defaults',argv)
            self.assertEqual(kwargs['env'],{'PATH':'/usr/bin:/bin','LC_ALL':'C'})
            p=original([sys.executable,'-c',code],**kwargs);children.append(p);return p
        try:
            with mock.patch.object(reader.subprocess,'Popen',side_effect=popen):
                if timeout:
                    with mock.patch.object(reader.select,'select',return_value=([],[],[])):
                        return reader.query('SELECT 1;\n','/run/test.sock',time.monotonic()+10)
                return reader.query('SELECT 1;\n','/run/test.sock',time.monotonic()+10)
        finally:
            self.assertTrue(children);self.assertIsNotNone(children[0].poll())
    def test_column_names_not_offsets(self):
        self.assertEqual(self.child_query("import sys;sys.stdin.read();print('b\\ta');print('2\\t1')"),[{'a':'1','b':'2'}])
    def test_oversized_output_and_cleanup(self):
        with self.assertRaisesRegex(reader.Failure,'query_failure'):
            self.child_query("import sys;sys.stdin.read();sys.stdout.write('x'*70000)")
    def test_timeout_and_cleanup(self):
        with self.assertRaisesRegex(reader.Failure,'timeout'):
            self.child_query("import sys;sys.stdin.read()",timeout=True)
    def test_raw_errors_discarded(self):
        with self.assertRaisesRegex(reader.Failure,'^authentication_denied$'):
            self.child_query("import sys;sys.stdin.read();sys.stderr.write('ERROR 1045 secret SQL password');sys.exit(1)")
    def test_malformed_rows_and_duplicate_columns(self):
        for output in ('a\ta\n1\t2','a\tb\n1'):
            with self.assertRaises(reader.Failure):self.child_query('import sys;sys.stdin.read();print('+repr(output)+')')
if __name__=='__main__':unittest.main()
