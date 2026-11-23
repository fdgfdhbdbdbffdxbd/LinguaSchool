import os
os.environ['LINGUA_FACTORY_ONLY'] = '1'
import re
import unittest
from datetime import timedelta
from cryptography.fernet import Fernet
from flask import g
from flask.testing import FlaskClient
from app import create_app, db, User, Course, Enrollment, Homework, Submission, Attempt, Audit, LoginSession, passwords, now

class IsolatedClient(FlaskClient):
    def open(self, *args, **kwargs):
        # The fixture keeps an app context for DB assertions. Reset request caches
        # that otherwise survive this artificial context across HTTP requests.
        for key in ('csrf_token', 'csrf_valid', '_login_user'):
            g.pop(key, None)
        return super().open(*args, **kwargs)

class SecurityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.hash = passwords.hash('CorrectPassword123!')

    def setUp(self):
        self.app = create_app({'TESTING':True,'SECRET_KEY':'test-only-secret','FIELD_KEY':Fernet.generate_key().decode(),'SQLALCHEMY_DATABASE_URI':'sqlite:///:memory:'})
        self.context = self.app.app_context()
        self.context.push()
        db.create_all()
        for i,role in enumerate(['admin','teacher','student','student','teacher'],1):
            db.session.add(User(id=i,email=f'u{i}@test.local',name=f'User {i}',role=role,password_hash=self.hash))
        db.session.flush()
        db.session.add(Course(id=1,title='English',level='A1',teacher_id=2,content='PRIVATE LESSON'))
        db.session.flush()
        db.session.add(Enrollment(user_id=3,course_id=1))
        db.session.add(Homework(id=1,course_id=1,title='Task',body='Write',due=now()+timedelta(days=1)))
        db.session.commit()
        self.app.test_client_class = IsolatedClient
        self.client=self.app.test_client()

    def tearDown(self):
        db.session.remove()
        db.drop_all()
        self.context.pop()

    def token(self,path):
        response=self.client.get(path)
        self.assertEqual(response.status_code,200)
        match=re.search(r'name="csrf_token" value="([^"]+)"',response.text)
        self.assertIsNotNone(match)
        return match.group(1)

    def login(self,uid):
        response=self.client.post('/login',data={'csrf_token':self.token('/login'),'email':f'u{uid}@test.local','password':'CorrectPassword123!'})
        self.assertEqual(response.status_code,302)

    def test_csrf_blocks_login(self):
        self.assertEqual(self.client.post('/login',data={'email':'x','password':'y'}).status_code,400)
        self.assertEqual(db.session.scalar(db.select(Audit.action)), 'csrf_blocked')

    def test_sql_injection_does_not_authenticate(self):
        self.client.post('/login',data={'csrf_token':self.token('/login'),'email':"' OR 1=1 --",'password':'anything'})
        self.assertEqual(self.client.get('/dashboard').status_code,302)
        self.assertEqual(db.session.scalar(db.select(db.func.count(User.id))),5)

    def test_access_is_object_scoped(self):
        self.login(4)
        self.assertEqual(self.client.get('/course/1').status_code,403)
        self.assertEqual(self.client.get('/homework/1').status_code,403)
        self.assertEqual(self.client.get('/analytics.csv').status_code,403)
        self.assertEqual(self.client.get('/manage').status_code,403)

    def test_other_teacher_is_denied(self):
        self.login(5)
        self.assertEqual(self.client.get('/course/1').status_code,403)

    def test_student_workflow_and_xss_escaping(self):
        self.login(3)
        self.assertIn('PRIVATE LESSON',self.client.get('/course/1').text)
        payload='<script>alert(1)</script>'
        self.client.post('/homework/1',data={'csrf_token':self.token('/homework/1'),'answer':payload})
        response=self.client.get('/homework/1')
        self.assertNotIn(payload,response.text)
        self.assertIn('&lt;script&gt;',response.text)
        self.assertEqual(db.session.scalar(db.select(Submission.answer)),payload)

    def test_test_score_computed_server_side(self):
        self.login(3)
        self.client.post('/test',data={'csrf_token':self.token('/test'),'score':'100','q0':"' OR 1=1 --"})
        self.assertEqual(db.session.scalar(db.select(Attempt.score)),0)

    def test_grading_and_authorization(self):
        db.session.add(Submission(homework_id=1,user_id=3,answer='Hello'))
        db.session.commit()
        self.login(2)
        response=self.client.post('/grade/1',data={'csrf_token':self.token('/homework/1'),'grade':'85','feedback':'Good'})
        self.assertEqual(response.status_code,302)
        self.assertEqual(db.session.get(Submission,1).grade,85)

    def test_logout_revokes_server_session(self):
        self.login(3)
        self.client.post('/logout',data={'csrf_token':self.token('/dashboard')})
        self.assertEqual(db.session.scalar(db.select(db.func.count(LoginSession.id))),0)
        self.assertEqual(self.client.get('/dashboard').status_code,302)

    def test_admin_pages_and_export(self):
        self.login(1)
        for path in ['/','/dashboard','/manage','/analytics','/analytics.csv','/course/1','/homework/1']:
            self.assertEqual(self.client.get(path).status_code,200,path)
        self.assertIn('attempt_id',self.client.get('/analytics.csv').text)

    def test_registration_encrypts_phone_and_fixes_role(self):
        response=self.client.post('/register',data={'csrf_token':self.token('/register'),'email':'new@test.local','name':'New','password':'CorrectPassword123!','phone':'+79991234567','role':'admin'})
        self.assertEqual(response.status_code,302)
        u=db.session.scalar(db.select(User).filter_by(email='new@test.local'))
        self.assertEqual(u.role,'student')
        self.assertNotIn('+7999',u.phone_cipher)
        self.assertEqual(self.app.extensions['cipher'].decrypt(u.phone_cipher.encode()).decode(),'+79991234567')
        self.assertTrue(passwords.verify(u.password_hash,'CorrectPassword123!'))

    def test_admin_create_update_delete(self):
        self.login(1)
        for data in [{'action':'course','teacher_id':'2','title':'New','level':'A2','content':'Text'}, {'action':'update_course','course_id':'2','title':'Updated','content':'Next'}, {'action':'delete_course','course_id':'2'}]:
            data['csrf_token']=self.token('/manage')
            self.assertEqual(self.client.post('/manage',data=data).status_code,302)
        self.assertIsNone(db.session.get(Course,2))

    def test_session_expiry_and_headers(self):
        self.login(3)
        record=db.session.scalar(db.select(LoginSession))
        record.expires=now()-timedelta(seconds=1)
        db.session.commit()
        self.assertEqual(self.client.get('/dashboard').status_code,302)
        response=self.client.get('/')
        self.assertEqual(response.headers['X-Content-Type-Options'],'nosniff')
        self.assertIn("frame-ancestors 'none'",response.headers['Content-Security-Policy'])

    def test_seed_has_5000_rows_and_no_duplicates(self):
        db.drop_all()
        db.create_all()
        runner=self.app.test_cli_runner()
        result=runner.invoke(args=['seed'])
        self.assertEqual(result.exit_code,0,result.output)
        self.assertEqual(db.session.scalar(db.select(db.func.count(Attempt.id))),5000)
        self.assertNotEqual(runner.invoke(args=['seed']).exit_code,0)

if __name__=='__main__': unittest.main(verbosity=2)
