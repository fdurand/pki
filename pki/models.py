from django.template import Context, Template
from django.core.urlresolvers import reverse
from django.contrib.auth.models import User
from django.db import models

from pyasn1.codec.der import encoder, decoder
from pyasn1_modules import rfc2459, pem

from email import Encoders
from email.MIMEBase import MIMEBase
from email.MIMEText import MIMEText
from email.MIMEMultipart import MIMEMultipart
from email.Utils import COMMASPACE, formatdate


from OpenSSL import crypto
import datetime
import smtplib
import hashlib
import string
import os


class CA(models.Model):
    cn = models.CharField(max_length=20,unique=1)
    mail = models.EmailField()
    organisation = models.CharField(max_length=40)
    ou = models.CharField(max_length=20,unique=1)
    country = models.CharField(max_length=2, default='CA')
    state = models.CharField(max_length=40)
    locality = models.CharField(max_length=40)
    key_type = models.IntegerField(choices=((crypto.TYPE_RSA, 'RSA'), (crypto.TYPE_DSA, 'DSA')))
    key_size = models.IntegerField(choices=((512, '512'), (1024, '1024'), (2048, '2048')))
    digest = models.CharField(max_length=10, choices=(('md5', 'md5'),('sha1', 'sha1')))
    key_usage = models.CharField(max_length=50,blank=1)
    extended_key_usage = models.CharField(max_length=50,blank=1)
    days = models.IntegerField(max_length=4)
    ca_key = models.TextField(blank=1,null=1)
    ca_cert = models.TextField(blank=1,null=1)
    issuerKeyHashmd5 = models.TextField(blank=1,null=1,max_length=33)
    issuerKeyHashsha1 = models.TextField(blank=1,null=1,max_length=41)
    issuerKeyHashsha256 = models.TextField(blank=1,null=1,max_length=65)
    issuerKeyHashsha512 = models.TextField(blank=1,null=1,max_length=129)
    def sign(self):
        k = crypto.PKey()
        k.generate_key(self.key_type, self.key_size)
        cert = crypto.X509()
        subj = cert.get_subject()
        setattr(subj, 'CN', self.cn)
        setattr(subj, 'emailAddress', self.mail)
        setattr(subj, 'ST', self.state)
        setattr(subj, 'O', self.organisation)
        setattr(subj, 'C', self.country)
        cert.set_serial_number(1000)
        cert.gmtime_adj_notBefore(0)
        cert.gmtime_adj_notAfter(self.days * 24 * 60 * 60)
        cert.set_issuer(cert.get_subject())
        cert.set_pubkey(k)
        if self.key_usage:
            cert.add_extensions([crypto.X509Extension("keyUsage", True,self.key_usage)])
        if self.extended_key_usage:
            cert.add_extensions([crypto.X509Extension("extendedKeyUsage", True,self.extended_key_usage)])
        cert.sign(k, self.digest)
        self.ca_key = crypto.dump_privatekey(crypto.FILETYPE_PEM, k)
        self.ca_cert = crypto.dump_certificate(crypto.FILETYPE_PEM, cert)
        certType = rfc2459.Certificate()
        substrate = crypto.dump_certificate(crypto.FILETYPE_ASN1, cert)
        certif, rest = decoder.decode(substrate, asn1Spec=certType)
        issuerTbsCertificate = certif.getComponentByName('tbsCertificate')
        issuerSubjectPublicKey = issuerTbsCertificate.getComponentByName('subjectPublicKeyInfo').getComponentByName('subjectPublicKey')
        self.issuerKeyHashmd5 = hashlib.md5(
            valueOnlyBitStringEncoder(issuerSubjectPublicKey)
            ).hexdigest()
        self.issuerKeyHashsha1 = hashlib.sha1(
            valueOnlyBitStringEncoder(issuerSubjectPublicKey)
            ).hexdigest()
        self.issuerKeyHashsha256 = hashlib.sha256(
            valueOnlyBitStringEncoder(issuerSubjectPublicKey)
            ).hexdigest()
        self.issuerKeyHashsha512 = hashlib.sha512(
            valueOnlyBitStringEncoder(issuerSubjectPublicKey)
            ).hexdigest()
    def get_absolute_url(self):
        return reverse('ca_update', kwargs={'pk': self.pk})
    def __str__(self):
        return self.cn
    def pkcs12(self, passphrase):
        p12 = crypto.PKCS12()
        key = crypto.load_privatekey(crypto.FILETYPE_PEM, self.ca_key)
        cert = crypto.load_certificate(crypto.FILETYPE_PEM, self.ca_cert)
        p12.set_privatekey(key)
        p12.set_certificate(cert)
        return crypto.dump_pkcs12(p12,passphrase, "")

class CertProfile(models.Model):
    name = models.CharField(max_length=20,unique=1)
    ca = models.ForeignKey(CA)
    crl_path = models.CharField(max_length=150,unique=1)
    validity = models.IntegerField()
    key_type = models.IntegerField(choices=((crypto.TYPE_RSA, 'RSA'), (crypto.TYPE_DSA, 'DSA')))
    key_size = models.IntegerField(choices=((512, '512'), (1024, '1024'),(2048, '2048')))
    digest = models.CharField(max_length=10, choices=(('md5', 'md5'),('sha1', 'sha1')))
    key_usage = models.CharField(max_length=50,blank=1)
    extended_key_usage = models.CharField(max_length=50,blank=1)
    p12_smtp_server = models.CharField(max_length=30)
    p12_mail_password = models.BooleanField()
    p12_mail_subject = models.CharField(max_length=30,blank=1)
    p12_mail_from = models.CharField(max_length=50,blank=1)
    p12_mail_header = models.TextField(blank=1)
    p12_mail_footer = models.TextField(blank=1)
    def get_absolute_url(self):
        return reverse('profile_update', kwargs={'pk': self.pk})
    def __str__(self):
        return self.name

class Cert(models.Model):
    REVOKE_REASON = (
        ('unspecified', 'reason is unknown'),
        ('keyCompromise', 'private key has been compromised'),
        ('cACompromise', 'certificate authority has been compromised'),
        ('affiliationChanged', 'affiliation has been changed'),
        ('superseded', 'certificate has been superseded'),
        ('cessationOfOperation' ,'cessation of operation'),
        ('certificateHold', 'certificate is on hold'),
        ('removeFromCRL', 'certificate was previously in a CRL, but is now valid'),
        ('privilegeWithdrawn', 'privilege has been withdrawn'),
        ('aACompromise', 'attribute authority has been compromised'),
        )
    cn = models.CharField(max_length=20,unique=1)
    mail = models.EmailField()
    x509 = models.TextField(blank=1,null=1)
    st = models.CharField(max_length=40)
    organisation = models.CharField(max_length=40)
    country = models.CharField(max_length=2, default='CA')
    pkey = models.TextField(blank=1,null=1)
    profile = models.ForeignKey(CertProfile)
    valid_until = models.DateTimeField(auto_now_add=1,blank=1,null=1)
    date = models.DateTimeField(auto_now_add=1,blank=1,null=1)
    revoked = models.DateTimeField(blank=1,null=1)
    CRLReason = models.CharField(max_length=20,choices=REVOKE_REASON, blank=1,null=1)
    userIssuerHashmd5 = models.TextField(blank=1,null=1,max_length=33)
    userIssuerHashsha1 = models.TextField(blank=1,null=1,max_length=41)
    userIssuerHashsha256 = models.TextField(blank=1,null=1,max_length=65)
    userIssuerHashsha512 = models.TextField(blank=1,null=1,max_length=129)
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
        req.sign(pkey, self.profile.digest)
        self.pkey = crypto.dump_privatekey(crypto.FILETYPE_PEM, pkey)
        x509 = crypto.X509()
        x509.set_subject(req.get_subject())
        x509.set_pubkey(req.get_pubkey())
        cacert = crypto.load_certificate(crypto.FILETYPE_PEM, self.profile.ca.ca_cert)
        cakey = crypto.load_privatekey(crypto.FILETYPE_PEM, self.profile.ca.ca_key)
        x509.set_issuer(cacert.get_subject())
        x509.set_serial_number(self.id)
        x509.gmtime_adj_notBefore(0)
        self.valid_until = self.date + datetime.timedelta(days=self.profile.validity)
        delta = self.valid_until.date() - self.date.date();
        x509.gmtime_adj_notAfter(delta.days * 60 * 60 * 24)
        if self.profile.key_usage:
            x509.add_extensions([crypto.X509Extension("keyUsage", True,str(self.profile.key_usage))])
        if self.profile.extended_key_usage:
            x509.add_extensions([crypto.X509Extension("extendedKeyUsage", True, str(self.profile.extended_key_usage))])
        x509.sign(cakey, self.profile.digest)
        self.x509 = crypto.dump_certificate(crypto.FILETYPE_PEM, x509)
        certType = rfc2459.Certificate()
        substrate = crypto.dump_certificate(crypto.FILETYPE_ASN1, x509)
        cert, rest = decoder.decode(substrate, asn1Spec=certType)
        userTbsCertificate = cert.getComponentByName('tbsCertificate')
        userIssuer = userTbsCertificate.getComponentByName('issuer')
        self.userIssuerHashmd5 = hashlib.md5(
            encoder.encode(userIssuer)
            ).hexdigest()
        self.userIssuerHashsha1 = hashlib.sha1(
            encoder.encode(userIssuer)
            ).hexdigest()
        self.userIssuerHashsha256 = hashlib.sha256(
            encoder.encode(userIssuer)
            ).hexdigest()
        self.userIssuerHashsha512 = hashlib.sha512(
            encoder.encode(userIssuer)
            ).hexdigest()
    def get_absolute_url(self):
        return "/pki/cert/"
    def pkcs12(self, passphrase):
        p12 = crypto.PKCS12()
        key = crypto.load_privatekey(crypto.FILETYPE_PEM, self.pkey)
        cert = crypto.load_certificate(crypto.FILETYPE_PEM, self.x509 + "\n" + self.profile.ca.ca_cert)
        p12.set_privatekey(key)
        p12.set_certificate(cert)
        return p12.export(passphrase)
    def send_password(self, passphrase):
        msg = MIMEMultipart()
        msg['From'] = self.profile.p12_mail_from
        msg['To'] = self.mail
        msg['Date'] = formatdate(localtime=True)
        msg['Subject'] = self.profile.p12_mail_subject
        Text = Template("Dear {{ cn }} {{ header }} {{ password }} {{ footer }}")
        msg.attach(MIMEText(Text.render(Context({'cn': self.cn,'header': self.profile.p12_mail_header, 'footer': self.profile.p12_mail_footer, 'password': passphrase})), 'plain', 'utf-8'))
# 	pdf = MIMEBase('application', "octet-stream")
#       pdf.set_payload(open("/help.pdf").read())
#	Encoders.encode_base64(pdf)
#	pdf.add_header('Content-Disposition', 'attachment; filename="aide.pdf"')
#	msg.attach(pdf)
        smtp = smtplib.SMTP(self.profile.p12_smtp_server)
        smtp.sendmail(self.profile.p12_mail_from, self.mail, msg.as_string())
        smtp.close()
    def send_cert(self, passphrase):
        msg = MIMEMultipart()
        msg['From'] = self.profile.p12_mail_from
        msg['To'] = self.mail
        msg['Date'] = formatdate(localtime=True)
        msg['Subject'] = self.profile.p12_mail_subject
        msg.attach(MIMEText(self.profile.p12_mail_header + ' ' + passphrase + "\n" + self.profile.p12_mail_footer, 'plain', 'utf-8'))
        part = MIMEBase('application', "octet-stream")
        part.set_payload(self.pkcs12(passphrase))
        Encoders.encode_base64(part)
        part.add_header('Content-Disposition', 'attachment; filename="%s.p12"' % string.replace(self.cn, ' ', '_'))
        msg.attach(part)
# 	pdf = MIMEBase('application', "octet-stream")
#       pdf.set_payload(open("/help.pdf").read())
#	Encoders.encode_base64(pdf)
#	pdf.add_header('Content-Disposition', 'attachment; filename="aide.pdf"')
#	msg.attach(pdf)
        smtp = smtplib.SMTP(self.profile.p12_smtp_server)
        smtp.sendmail(self.profile.p12_mail_from, self.mail, msg.as_string())
        smtp.close()
    class Meta:
        db_table = 'cert'

class ValueOnlyBitStringEncoder(encoder.encoder.BitStringEncoder):
    # These methods just do not encode tag and length fields of TLV
    def encodeTag(self, *args): return ''
    def encodeLength(self, *args): return ''
    def encodeValue(*args):
        substrate, isConstructed = encoder.encoder.BitStringEncoder.encodeValue(*args)
        # OCSP-specific hack follows: cut off the "unused bit count"
        # encoded bit-string value.
        return substrate[1:], isConstructed

    def __call__(self, bitStringValue):
        return self.encode(None, bitStringValue, defMode=1, maxChunkSize=0)

valueOnlyBitStringEncoder = ValueOnlyBitStringEncoder()

class rest(models.Model):
    name = models.CharField(max_length=20,unique=1)
    profile = models.ForeignKey(CertProfile)
    url = models.URLField()
    allowed_users = models.ManyToManyField(User)

    def get_absolute_url(self):
        return reverse('rest_update', kwargs={'pk': self.pk})
