from django.template.loader import get_template
from django.template import Context
from django.conf import settings
from django.db import models
from time import sleep
import string
import ldap
import operator
from pysqlite2 import dbapi2 as sqlite
from OpenSSL import crypto
import datetime, os, time
import smtplib
from email.MIMEMultipart import MIMEMultipart
from email.MIMEBase import MIMEBase
from email.MIMEText import MIMEText
from email.Utils import COMMASPACE, formatdate
from email import Encoders
import os

class Conf(models.Model):
    var = models.CharField(maxlength=20,unique=1)
    value = models.CharField(maxlength=20)
    class Meta:
        db_table = 'conf'

class Log(models.Model):
    LOG_LEVELS = (
        ('emerg', 'emerg'),
        ('alert', 'alert'),
        ('crit',  'crit'),
        ('error', 'error'),
        ('warn',  'warn'),
        ('notice','notice'),
        ('info',  'info'),
        ('debug', 'debug'),
        )
    desc = models.CharField(maxlength=20,unique=1)
    level = models.CharField(maxlength=10,blank=1,choices=LOG_LEVELS)
    format = models.CharField(maxlength=50, blank=1)
    file = models.CharField(maxlength=50)
    def __str__(self):
        return self.desc
    class Meta:
        db_table = 'log'


class Intf(models.Model):
    SSL_ENGINES = (
        ('cswift',   'CryptoSwift'),
        ('chil',     'nCipher'),
        ('atalla',   'Atalla'),
        ('nuron',    'Nuron'),
        ('ubsec',    'UBSEC'),
        ('aep',      'Aep'),
        ('sureware', 'SureWare'),
        ('4758cca',  'IBM 4758 CCA'),
        )
    desc = models.CharField(maxlength=20,unique=1)
    ip = models.IPAddressField()
    port = models.IntegerField()
    ssl_engine = models.CharField(maxlength=10,blank=1,choices=SSL_ENGINES)
    log = models.ForeignKey(Log)
    sso_portal = models.CharField(maxlength=20,blank=1,null=1)
    cert = models.TextField(blank=1,null=1)
    key = models.TextField(blank=1,null=1)
    ca = models.TextField(blank=1,null=1)

    def get_absolute_url(self):
        return "/intf/"

    def __str__(self):
        return self.desc

    def conf(self):
        t = get_template("vulture_httpd.conf")
        c = Context({"VultureID" : self.id,
                     "VulturePath" : settings.PATH,
                     "PerlSwitches" : settings.PERL_SWITCHES,
                     "dbname" : settings.DATABASE_NAME,
                     "app_list" : App.objects.filter(intf=self.id),
                     "ip" : self.ip,
                     "port" : self.port,
                     "ssl" : self.cert,
                     })
        return t.render(c)

    def write(self):
        f=open("%s/%s.conf" % (settings.PATH, self.id), 'w')
        f.write(self.conf())
        if self.cert:
            f=open("%s/%s.crt" % (settings.PATH, self.id), 'w')
            f.write(self.cert)
        if self.key:
            f=open("%s/%s.key" % (settings.PATH, self.id), 'w')
            f.write(self.key)
        if self.ca:
            f=open("%s/%s.chain" % (settings.PATH, self.id), 'w')
            f.write(self.ca)
            
    def pid(self):
        try:
            pid = string.strip((open("%s/%s.pid" % (settings.PATH, self.id), 'r').read()))
        except:
            return None
        pidof = str(os.popen("pidof %s" % settings.HTTPD_PATH).read()).split()
        if len(pidof) and pid not in pidof:
            return None
        return pid

    def need_restart(self):
        try:
            f=open("%s/%s.conf" % (settings.PATH, self.id), 'r')
        except:
            return True
        if f.read() != self.conf() :
            return True
        if self.ca:
	        try:
	            f=open("%s/%s.chain" % (settings.PATH, self.id), 'r')
	        except:
	            return True
	        if f.read() != self.ca :
	            return True
        if self.cert:
	        try:
	            f=open("%s/%s.crt" % (settings.PATH, self.id), 'r')
	        except:
	            return True
	        if f.read() != self.cert :
	            return True
        if self.key:
	        try:
	            f=open("%s/%s.key" % (settings.PATH, self.id), 'r')
	        except:
	            return True
	        if f.read() != self.key :
	            return True
    
    def k(self, cmd):
        return os.popen("%s -f %s/%s.conf -k %s 2>&1" % (settings.HTTPD_PATH, settings.PATH, self.id, cmd)).read()

    class Meta:
        db_table = 'if'

class Auth(models.Model):
    name = models.CharField(maxlength=20,unique=1)
    type = models.CharField(maxlength=20)
    def __str__(self):
        return self.name
    class Meta:
        db_table = 'auth'
    
class SQL(models.Model):
    SQL_DRIVERS = (
        ('SQLite', 'SQLite'),
        ('Pg', 'PostgreSQL'),
        )
    SQL_ALGOS = (
        ('plain', 'plain'),
        ('md5', 'md5'),
        ('sha1', 'sha1'),
        ('crypt', 'crypt'),
        )
    name = models.OneToOneField(Auth)
    driver = models.CharField(maxlength=10,choices=SQL_DRIVERS)
    database = models.CharField(maxlength=60)
    user = models.CharField(maxlength=20, blank=1)
    password = models.CharField(maxlength=20, blank=1)
    host = models.CharField(maxlength=20, blank=1)
    table = models.CharField(maxlength=20)
    user_column = models.CharField(maxlength=20)
    pass_column = models.CharField(maxlength=20)
    pass_algo = models.CharField(maxlength=10,choices=SQL_ALGOS)
    url_field = models.CharField(maxlength=20,blank=1)
    display_portal = models.BooleanField()
    def user_ko(self, user_ok):
        user_ko = []
        if self.driver == 'SQLite':
            con = sqlite.connect(self.database)
            cur = con.cursor()
            query = "select %s from %s" % (self.user_column, self.table)
            sep = " WHERE "
            for user in user_ok:
                query += sep + "%s != '%s'" % (self.user_column, user[0])
                sep = " AND "
            print query
            cur.execute(query)
            for user in cur:
                user_ko.append(('%s' % user, '%s' % user))
        return user_ko
    def get_absolute_url(self):
        return "/sql/"
    class Meta:
        db_table = 'sql'

class LDAP(models.Model):
    LDAP_ENC_SCHEMES = (
        ('none','none (usual port: 389)'),
        ('ldaps','ldaps (usual port: 636)'),
        ('start-tls','start-tls (usual port: 389)'),
        )
    LDAP_SCOPE = (
        (ldap.SCOPE_SUBTREE,'subtree (all levels under suffix)'),
        (ldap.SCOPE_ONELEVEL,'one (one level under suffix)'),
        (ldap.SCOPE_BASE,'base (the suffix entry only)'),        
        )
    LDAP_VERSIONS = (
        ('2','LDAP v2'),
        ('3','LDAP v3'),
        )
    name = models.OneToOneField(Auth)
    host = models.CharField(maxlength=20)
    port = models.IntegerField()
    protocol = models.IntegerField(choices=LDAP_VERSIONS)
    scheme = models.CharField(maxlength=10,choices=LDAP_ENC_SCHEMES, default="none")
    cacert_path = models.CharField(maxlength=20, blank=1, null=1)
    base_dn = models.CharField(maxlength=50)
    dn = models.CharField(maxlength=50)
    password = models.CharField(maxlength=20)
    user_attr = models.CharField(maxlength=20)
    user_scope = models.IntegerField(choices=LDAP_SCOPE)
    user_filter = models.CharField(maxlength=100)
    group_attr = models.CharField(maxlength=50)
    group_scope = models.IntegerField(choices=LDAP_SCOPE)
    group_filter = models.CharField(maxlength=100)
    group_member = models.CharField(maxlength=20)
    are_members_dn = models.BooleanField()
    url_attr = models.CharField(maxlength=20, blank=1)
    display_portal = models.BooleanField()

    def search(self, base_dn, scope, filter, attr):
        ko = []
        try:
            l = ldap.open(self.host)
            l.simple_bind_s(self.dn, self.password)
            result_id = l.search(base_dn, scope, filter, [attr])
            while 1:
                result_type, result_data = l.result(result_id, 0)
                if not result_data:
                    break
                if result_type == ldap.RES_SEARCH_ENTRY:
                    ko.append((result_data[0][1][attr][0], result_data[0][1][attr][0]))
        except ldap.LDAPError, error_message:
            print error_message
        return sorted(ko, key=operator.itemgetter(0))
    
    def user_ko(self, user_ok):
        user_filter = "(&"+self.user_filter
        for user in user_ok:
            user_filter += "(!("+self.user_attr+"="+user[0]+"))"
        user_filter += ")"
        return self.search(self.base_dn, self.user_scope, user_filter, self.user_attr)

    def group_ko(self, group_ok):
        group_filter = "(&"+self.group_filter
        for group in group_ok:
            group_filter += "(!("+self.group_attr+"="+group[0]+"))"
        group_filter += ")"
        return self.search(self.base_dn, self.group_scope, group_filter, self.group_attr)
    
    def get_absolute_url(self):
        return "/ldap/"
    class Meta:
        db_table = 'ldap'

class ACL(models.Model):
    name = models.OneToOneField(Auth, related_name='auth_name')
    auth = models.ForeignKey(Auth)
    def get_absolute_url(self):
        return "/acl/"
    class Meta:
        db_table = 'acl'

class UserOK(models.Model):
    acl = models.ForeignKey(ACL)
    user = models.CharField(maxlength=20,unique=1)

class GroupOK(models.Model):
    acl = models.ForeignKey(ACL)
    group = models.CharField(maxlength=20,unique=1)

class SSL(models.Model):
    SSL_REQUIRE = (
        ('optional', 'optional'),
        ('require', 'require'),
        )
    name = models.OneToOneField(Auth)
    require = models.CharField(maxlength=20, choices=SSL_REQUIRE)
    crt = models.CharField(maxlength=30)
    constraint = models.CharField(maxlength=30)
    def get_absolute_url(self):
        return "/ssl/"
    class Meta:
        db_table = 'ssl'

class User(models.Model):
    login = models.CharField(maxlength=20,unique=1)
    password = models.CharField(maxlength=20)
    is_admin = models.BooleanField()
    pki_operator = models.BooleanField()
    def get_absolute_url(self):
        return "/user/"
    class Meta:
        db_table = 'user'


class Profile(models.Model):
    user = models.CharField(maxlength=20)
#    field = models.ForeignKey(Field)
    value = models.CharField(maxlength=50)
    def get_absolute_url(self):
        return "/profile/"
    class Meta:
        db_table = 'profile'

class App(models.Model):
    name = models.CharField(maxlength=20,unique=1)
    desc = models.CharField(maxlength=20,blank=1)
    url = models.URLField(verify_exists=0)    
    intf = models.ForeignKey(Intf)
    alias = models.CharField(maxlength=150,blank=1)
    log = models.ForeignKey(Log)
    post_url = models.URLField(null=1,blank=1,verify_exists=0)
    remote_proxy = models.URLField(null=1,blank=1,verify_exists=0)
    up = models.BooleanField(default=1)
    timeout = models.IntegerField(null=1,blank=1)
    auth = models.ForeignKey(Auth,null=1,blank=1)
    def get_absolute_url(self):
        return "/app/"
    class Meta:
        db_table = 'app'

class Header(models.Model):
    HEADER_TYPE = (
        ('REMOTE_ADDR', 'REMOTE_ADDR'),
        ('SSL_CLIENT_I_DN', 'SSL_CLIENT_I_DN'),
        ('SSL_CLIENT_M_SERIAL', 'SSL_CLIENT_M_SERIAL'),
        ('SSL_CLIENT_S_DN', 'SSL_CLIENT_S_DN'),
        ('SSL_CLIENT_V_START', 'SSL_CLIENT_V_START'),
        ('SSL_CLIENT_V_END', 'SSL_CLIENT_V_END'),
        )
    name = models.CharField(maxlength=20,unique=1)
    type = models.CharField(maxlength=20,choices=HEADER_TYPE)
    value = models.CharField(maxlength=30,blank=1)
    app = models.ForeignKey(App)
    class Meta:
        db_table = 'header'

class CertProfile(models.Model):
    name = models.CharField(maxlength=20,unique=1)
    crl_path = models.CharField(maxlength=150,unique=1)
    ca_key = models.TextField()
    ca_cert = models.TextField()
    validity = models.IntegerField()
    key_type = models.IntegerField(choices=((crypto.TYPE_RSA, 'RSA'), (crypto.TYPE_DSA, 'DSA')))
    key_size = models.IntegerField(choices=((512, '512'), (1024, '1024')))
    digest = models.CharField(maxlength=10, choices=(('md5', 'md5'),('sha1', 'sha1')))
    p12_smtp_server = models.CharField(maxlength=30)
    p12_mail_password = models.BooleanField()
    p12_mail_subject = models.CharField(maxlength=30,blank=1)
    p12_mail_from = models.CharField(maxlength=50,blank=1)
    p12_mail_header = models.TextField(blank=1)
    p12_mail_footer = models.TextField(blank=1)
    def get_absolute_url(self):
        return "/pki/profile/"
    def __str__(self):
        return self.name

class Cert(models.Model):
    cn = models.CharField(maxlength=20,unique=1)
    mail = models.EmailField()
    x509 = models.TextField()
    st = models.CharField(maxlength=40)
    organisation = models.CharField(maxlength=40)
    country = models.CharField(maxlength=2, default='FR')
    pkey = models.TextField()
    profile = models.ForeignKey(CertProfile)
    valid_until = models.DateTimeField()
    date = models.DateTimeField(auto_now_add=1)
    revoked = models.DateTimeField(blank=1,null=1)
    def valid_until_str(self):
        return self.valid_until.strftime("%d/%m/%Y")
    def sign(self):
        req = crypto.X509Req()
        subj = req.get_subject()
        setattr(subj, 'CN', self.cn)
        setattr(subj, 'emailAddress', self.mail)
        setattr(subj, 'ST', self.st)
        setattr(subj, 'O', self.organisation)
        setattr(subj, 'C', self.country)
        pkey = crypto.PKey()
        pkey.generate_key(self.profile.key_type, self.profile.key_size)
        req.set_pubkey(pkey)
        req.sign(pkey, 'md5')
        self.pkey = crypto.dump_privatekey(crypto.FILETYPE_PEM, pkey)
        x509 = crypto.X509()
        x509.set_subject(req.get_subject())
        x509.set_pubkey(req.get_pubkey())
        cacert = crypto.load_certificate(crypto.FILETYPE_PEM, self.profile.ca_cert)
        cakey = crypto.load_privatekey(crypto.FILETYPE_PEM, self.profile.ca_key)
        x509.set_issuer(cacert.get_subject())
        x509.set_serial_number(self.id)
        x509.gmtime_adj_notBefore(0)
        delta = self.valid_until.date() - self.date.date();
        x509.gmtime_adj_notAfter(delta.days * 60 * 60 * 24)
        x509.sign(cakey, self.profile.digest)
        self.x509 = crypto.dump_certificate(crypto.FILETYPE_PEM, x509)
    def get_absolute_url(self):
        return "/pki/cert/"
    def pkcs12(self, passphrase):
        p12 = crypto.PKCS12()
        key = crypto.load_privatekey(crypto.FILETYPE_PEM, self.pkey)
        cert = crypto.load_certificate(crypto.FILETYPE_PEM, self.x509 + "\n" + self.profile.ca_cert)
        p12.set_privatekey(key)
        p12.set_certificate(cert)
        return crypto.dump_pkcs12(p12,passphrase, "")
    def send(self, to, passphrase):
        msg = MIMEMultipart()
        msg['From'] = self.profile.p12_mail_from
        msg['To'] = to
        msg['Date'] = formatdate(localtime=True)
        msg['Subject'] = self.profile.p12_mail_subject
        msg.attach(MIMEText(self.profile.p12_mail_header + ' ' + passphrase + "\n" + self.profile.p12_mail_footer, 'plain', 'utf-8'))
        part = MIMEBase('application', "octet-stream")
        part.set_payload(self.pkcs12(passphrase))
        Encoders.encode_base64(part)
        part.add_header('Content-Disposition', 'attachment; filename="%s.p12"' % string.replace(self.cn, ' ', '_'))
        msg.attach(part)
# 	pdf = MIMEBase('application', "octet-stream")
#       pdf.set_payload(open("/opt/rooster/aide.pdf").read())
#	Encoders.encode_base64(pdf)
#	pdf.add_header('Content-Disposition', 'attachment; filename="aide.pdf"')
#	msg.attach(pdf)
        smtp = smtplib.SMTP(self.profile.p12_smtp_server)
        smtp.sendmail(self.profile.p12_mail_from, to, msg.as_string())
        smtp.close()
    class Meta:
        db_table = 'cert'
