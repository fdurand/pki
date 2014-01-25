from www.vulture.models import *
from django.http import HttpResponseRedirect
from django.shortcuts import render_to_response
from django.views.generic.list_detail import object_list
from django.views.generic.create_update import update_object, create_object, delete_object
from django.template import loader
from django.template import RequestContext
from django.http import Http404, HttpResponse, HttpResponseRedirect
from django.core.exceptions import ObjectDoesNotExist, ImproperlyConfigured
from django.core.xheaders import populate_xheaders
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.decorators import user_passes_test
from django.utils.html import escape
from django import forms
from time import sleep
import datetime
import time
from django.core import validators
from django.db.models import Q
import md5
from random import choice
from django.core.paginator import ObjectPaginator, InvalidPage
from django.db import connection

def is_administrator(user):
    cursor = connection.cursor()
    cursor.execute("SELECT 1 FROM user WHERE login = %s AND is_admin=1", [user.username])
    return cursor.fetchone()

def is_pki_op(user):
    cursor = connection.cursor()
    cursor.execute("SELECT 1 FROM user WHERE login = %s AND (is_admin=1 OR pki_operator=1)", [user.username])
    return cursor.fetchone()

def start(request, intf_id):
    Intf.objects.get(pk=intf_id).write()
    k_output = Intf.objects.get(pk=intf_id).k('start')
    sleep(1)
    return render_to_response('vulture/intf_list.html',
                              {'object_list': Intf.objects.all(), 'k_output': k_output, 'user' : request.user })
start = user_passes_test(lambda u: is_administrator(u), login_url='/logon/')(start)


def stop(request, intf_id):
    k_output = Intf.objects.get(pk=intf_id).k('stop')
    sleep(1)
    return render_to_response('vulture/intf_list.html',
                              {'object_list': Intf.objects.all(), 'k_output': k_output, 'user' : request.user})

stop = user_passes_test(lambda u: is_administrator(u), login_url='/logon/')(stop)


def reload(request, intf_id):
    Intf.objects.get(pk=intf_id).write()
    k_output = Intf.objects.get(pk=intf_id).k('graceful')
    return render_to_response('vulture/intf_list.html',
                              {'object_list': Intf.objects.all(), 'k_output': k_output, 'user' : request.user})

reload = user_passes_test(lambda u: is_administrator(u), login_url='/logon/')(reload)

def logon(request):    
    if request.POST:
        user = authenticate(username=request.POST['username'], password=request.POST['password'])
        if user is not None:
            login(request, user)
            request.session['version'] = '2.0'
            if is_pki_op(user):
                return HttpResponseRedirect("/pki/")
            return HttpResponseRedirect("/user/")
    logout(request)
    return render_to_response('logon.html')

def vulture_object_list(*args, **kwargs):
    return object_list(*args, **kwargs)

vulture_object_list = user_passes_test(lambda u: is_administrator(u), login_url='/logon/')(vulture_object_list)

def vulture_update_object(*args, **kwargs):
    return update_object(*args, **kwargs)

vulture_update_object = user_passes_test(lambda u: is_administrator(u), login_url='/logon/')(vulture_update_object)

def vulture_create_object(*args, **kwargs):
    return create_object(*args, **kwargs)

vulture_create_object = user_passes_test(lambda u: is_administrator(u), login_url='/logon/')(vulture_create_object)

def vulture_delete_object(*args, **kwargs):
    return delete_object(*args, **kwargs)

vulture_delete_object = user_passes_test(lambda u: is_administrator(u), login_url='/logon/')(vulture_delete_object)

def switch_app(request, object_id):
    try:
        app = App.objects.get(id=object_id)
    except App.DoesNotExist:
        return HttpResponseRedirect("/app/")
    if not app.up:
        app.up = True
    else:
        app.up = False
    app.save()
    return HttpResponseRedirect("/app/")

switch_app = user_passes_test(lambda u: is_administrator(u), login_url='/logon/')(switch_app)


class UserManipulator(forms.Manipulator):
    def __init__(self):
        self.fields = (
            forms.TextField(field_name="login", is_required=True, validator_list=[self.isUnique, validators.isAlphaNumeric]),
            forms.PasswordField(field_name="password", is_required=True),
            forms.CheckboxField(field_name="is_admin"),
            forms.CheckboxField(field_name="pki_operator"),
            )

class UserAddManipulator(UserManipulator):
    def isUnique(self, field_data, all_data):
        if User.objects.filter(login=field_data).count():
            raise validators.ValidationError("User %s already exists" % field_data)
        
    def save(self, new_data):
        user = User(login=new_data['login'],password=md5.new(new_data['password']).hexdigest(),is_admin=new_data['is_admin'], pki_operator=new_data['pki_operator'])
        user.save()

class UserChangeManipulator(UserManipulator):
    def isUnique(self, field_data, all_data):
        if User.objects.filter(login=field_data).exclude(id=self.id).count():
            raise validators.ValidationError("User %s already exists" % field_data)
        
    def save(self, new_data):
        user = User.objects.get(id=self.id)
        user.login=new_data['login']
        user.is_admin=new_data['is_admin']
        user.pki_operator=new_data['pki_operator']
        if new_data['password'] != user.password:
            user.password = md5.new(new_data['password']).hexdigest()
        user.save()

class SSLManipulator(forms.Manipulator):
    def __init__(self):
        self.fields = (
            forms.TextField(field_name="name", is_required=True, validator_list=[self.isUnique, validators.isAlphaNumeric]),
            forms.SelectField(field_name="require", choices=SSL.SSL_REQUIRE),
            forms.LargeTextField(field_name="crt", is_required=True),
            )
    
class SSLAddManipulator(SSLManipulator):
    def isUnique(self, field_data, all_data):
        if Auth.objects.filter(name=field_data).count():
            raise validators.ValidationError("An authentication already exists with that name")
        
    def save(self, new_data):
        auth = Auth(name=new_data['name'],type='ssl')
        auth.save()
        ssl = SSL(name=auth, require=new_data['require'], crt=new_data['crt'])
        ssl.save()

class SSLChangeManipulator(SSLManipulator):
    def isUnique(self, field_data, all_data):
        if Auth.objects.filter(name=field_data).exclude(id=self.id).count():
                        raise validators.ValidationError("An authentication already exists with that name")

    def save(self, new_data):
        ssl = SSL.objects.get(name=self.id)
        auth = ssl.name
        auth.name = new_data['name']
        auth.type='ssl'
        auth.save()
        ssl.require = new_data['require']
        ssl.crt = new_data['crt']
        ssl.save()

class AuthSelectField(forms.SelectField):
    def render(self, data):
        output = ['<select id="%s" class="v%s%s" name="%s" size="%s" onchange="javascript:submit();">' % \
            (self.get_id(), self.__class__.__name__,
             self.is_required and ' required' or '', self.field_name, self.size)]
        str_data = str(data) # normalize to string
        for value, display_name in self.choices:
            selected_html = ''
            if str(value) == str_data:
                selected_html = ' selected="selected"'
            output.append('    <option value="%s"%s>%s</option>' % (escape(value), selected_html, escape(display_name)))
        output.append('  </select>')
        return '\n'.join(output)

class ACLManipulator(forms.Manipulator):
    def __init__(self, user_ko, user_ok, group_ko, group_ok):
        auth_choices = [('', '---')]
        for name in Auth.objects.exclude(type='acl').exclude(type='ssl'):
            auth_choices.append((name, name))
        self.fields = (
            forms.TextField(field_name="name", is_required=True, validator_list=[self.isUnique, validators.isAlphaNumeric]),
            AuthSelectField(field_name="auth", is_required=True, choices=auth_choices),
            forms.SelectMultipleField(field_name="user_ko", choices=user_ko, size=10),
            forms.SelectMultipleField(field_name="user_ok", choices=user_ok, size=10),
            forms.SelectMultipleField(field_name="group_ko", choices=group_ko, size=10),
            forms.SelectMultipleField(field_name="group_ok", choices=group_ok, size=10),
            )

class ACLAddManipulator(ACLManipulator):
    def isUnique(self, field_data, all_data):
        if Auth.objects.filter(name=field_data).count():
            raise validators.ValidationError("An authentication already exists with that name")
        
    def save(self, new_data):
        a = Auth(name=new_data['name'],type='acl')
        a.save()
        acl = ACL(name=a, auth=Auth.objects.get(name=new_data['auth']))
        acl.save()
        self.id = a.id

class ACLChangeManipulator(ACLManipulator):
    def isUnique(self, field_data, all_data):
        if Auth.objects.filter(name=field_data).exclude(id=self.id).count():
            raise validators.ValidationError("An authentication already exists with that name")

    def save(self, new_data):
        acl = ACL.objects.get(name=self.id)
        auth = acl.name
        auth.name = new_data['name']
        auth.type='acl'
        auth.save()
        acl.auth = Auth.objects.get(name=new_data['auth'])
        acl.save()


class DBSelectField(forms.SelectField):
    def render(self, data):
        output = ['<select id="%s" class="v%s%s" name="%s" size="%s" onchange="javascript:dbchange();">' % \
            (self.get_id(), self.__class__.__name__,
             self.is_required and ' required' or '', self.field_name, self.size)]
        str_data = str(data) # normalize to string
        for value, display_name in self.choices:
            selected_html = ''
            if str(value) == str_data:
                selected_html = ' selected="selected"'
            output.append('    <option value="%s"%s>%s</option>' % (escape(value), selected_html, escape(display_name)))
        output.append('  </select>')
        return '\n'.join(output)


class SQLManipulator(forms.Manipulator):
    def __init__(self):
        self.fields = (
            forms.TextField(field_name="name", is_required=True, validator_list=[self.isUnique, validators.isAlphaNumeric]),
            DBSelectField(field_name="driver", choices=SQL.SQL_DRIVERS),
            forms.TextField(field_name="database", is_required=True, maxlength=60),
            forms.TextField(field_name="user", maxlength=60),
            forms.TextField(field_name="password", maxlength=60),
            forms.TextField(field_name="host", maxlength=60),
            forms.TextField(field_name="table", maxlength=60),
            forms.TextField(field_name="user_column", is_required=True, maxlength=60),
            forms.TextField(field_name="pass_column", is_required=True, maxlength=60),
            forms.SelectField(field_name="pass_algo", choices=SQL.SQL_ALGOS),
            forms.TextField(field_name="url_field", maxlength=20),
            forms.CheckboxField(field_name="display_portal"),
            )

class SQLAddManipulator(SQLManipulator):
    def isUnique(self, field_data, all_data):
        if Auth.objects.filter(name=field_data).count():
            raise validators.ValidationError("An authentication already exists with that name")
        
    def save(self, new_data):
        auth = Auth(name=new_data['name'],type='sql')
        auth.save()
        sql = SQL(name=auth, driver=new_data['driver'], database=new_data['database'], user=new_data['user'], password=new_data['password'],
                  host=new_data['host'], table=new_data['table'], user_column=new_data['user_column'], pass_column=new_data['pass_column'],
                  pass_algo=new_data['pass_algo'], url_field=new_data['url_field'], display_portal=new_data['display_portal'])
        sql.save()

class SQLChangeManipulator(SQLManipulator):        
    def isUnique(self, field_data, all_data):
        if Auth.objects.filter(name=field_data).exclude(id=self.id).count():
            raise validators.ValidationError("An authentication already exists with that name")

    def save(self, new_data):
        sql = SQL.objects.get(name=self.id)
        auth = sql.name
        auth.name = new_data['name']
        auth.type='sql'
        auth.save()
        sql.driver = new_data['driver']
        sql.database = new_data['database']
        sql.user = new_data['user']
        sql.password = new_data['password']
        sql.host = new_data['host']
        sql.table = new_data['table']
        sql.user_column = new_data['user_column']
        sql.pass_column = new_data['pass_column']
        sql.pass_algo = new_data['pass_algo']
        sql.url_field = new_data['url_field']
        sql.display_portal = new_data['display_portal']
        sql.save()

class LDAPManipulator(forms.Manipulator):
    def __init__(self):
        self.fields = (
            forms.TextField(field_name="name", is_required=1, validator_list=[self.isUnique, validators.isAlphaNumeric]),
            forms.TextField(field_name="host", maxlength=20, is_required=1),
            forms.IntegerField(field_name="port", is_required=1),
            forms.SelectField(field_name="protocol", choices=LDAP.LDAP_VERSIONS),
            forms.SelectField(field_name="scheme", choices=LDAP.LDAP_ENC_SCHEMES),
            forms.TextField(field_name="cacert_path", maxlength=20),
            forms.TextField(field_name="base_dn", maxlength=50, is_required=1),
            forms.TextField(field_name="dn", maxlength=50, is_required=1),
            forms.PasswordField(field_name="password", is_required=1, maxlength=20),
            forms.TextField(field_name="user_attr", maxlength=50, is_required=1),
            forms.SelectField(field_name="user_scope", choices=LDAP.LDAP_SCOPE),
            forms.TextField(field_name="user_filter", maxlength=100),
            forms.TextField(field_name="group_attr", maxlength=50, is_required=1),
            forms.SelectField(field_name="group_scope", choices=LDAP.LDAP_SCOPE),
            forms.TextField(field_name="group_filter", maxlength=100),
            forms.TextField(field_name="group_member", maxlength=20),
            forms.CheckboxField(field_name="are_members_dn"),
            forms.TextField(field_name="url_attr", maxlength=20),
            forms.CheckboxField(field_name="display_portal"),
            )
    
class LDAPAddManipulator(LDAPManipulator):
    def isUnique(self, field_data, all_data):
        if Auth.objects.filter(name=field_data).count():
            raise validators.ValidationError("An authentication already exists with that name")
        
    def save(self, new_data):
        auth = Auth(name=new_data['name'],type='ldap')
        auth.save()
        ldap = LDAP(name=auth, host=new_data['host'], port=new_data['port'], protocol=new_data['protocol'], scheme=new_data['scheme'],
                    cacert_path=new_data['cacert_path'], base_dn=new_data['base_dn'], dn=new_data['dn'], password=new_data['password'],
                    user_attr=new_data['user_attr'], user_scope=new_data['user_scope'], user_filter=new_data['user_filter'], group_attr=new_data['group_attr'],
                    group_scope=new_data['group_scope'], group_filter=new_data['group_filter'], group_member=new_data['group_member'],
                    are_members_dn=new_data['are_members_dn'], display_portal=new_data['display_portal'])
        ldap.save()

class LDAPChangeManipulator(LDAPManipulator):        
    def isUnique(self, field_data, all_data):
        if Auth.objects.filter(name=field_data).exclude(id=self.id).count():
            raise validators.ValidationError("An authentication already exists with that name")

    def save(self, new_data):
        ldap = LDAP.objects.get(name=self.id)
        auth = ldap.name
        auth.name = new_data['name']
        auth.type='ldap'
        auth.save()
        ldap.host = new_data['host']
        ldap.port = new_data['port']
        ldap.protocol = new_data['protocol']
        ldap.scheme = new_data['scheme']
        ldap.cacert_path = new_data['cacert_path']
        ldap.base_dn = new_data['base_dn']
        ldap.dn = new_data['dn']
        ldap.password = new_data['password']
        ldap.user_attr = new_data['user_attr']
        ldap.user_scope = new_data['user_scope']
        ldap.user_filter = new_data['user_filter']
        ldap.group_attr = new_data['group_attr']
        ldap.group_scope = new_data['group_scope']
        ldap.group_filter = new_data['group_filter']
        ldap.group_member = new_data['group_member']
        ldap.are_members_dn = new_data['are_members_dn']        
        ldap.url_attr = new_data['url_attr']
        ldap.display_portal = new_data['display_portal']
        ldap.save()

def create_user(request):
    manipulator = UserAddManipulator()
    if request.POST:
        new_data = request.POST.copy()
        errors = manipulator.get_validation_errors(new_data)
        if not errors:
            manipulator.do_html2python(new_data)
            manipulator.save(new_data)
            return HttpResponseRedirect("/user/")
    else:
        errors = new_data = {}
    form = forms.FormWrapper(manipulator, new_data, errors)
    return render_to_response('vulture/user_form.html', {'form': form, 'user' : request.user })

create_user = user_passes_test(lambda u: is_administrator(u), login_url='/logon/')(create_user)

def update_user(request, object_id):
    try:
        manipulator = UserChangeManipulator()
        manipulator.id = object_id
    except User.DoesNotExist:
        raise Http404
    if request.POST:
        new_data = request.POST.copy()
        errors = manipulator.get_validation_errors(new_data)
        if not errors:
            manipulator.do_html2python(new_data)
            manipulator.save(new_data)
            return HttpResponseRedirect("/user/")
    else:
        errors = {}
        user = User.objects.get(id=object_id)
        new_data = { 'login' : user.login, 'is_admin' : user.is_admin, 'password' : user.password, 'pki_operator': user.pki_operator }
    form = forms.FormWrapper(manipulator, new_data, errors)
    return render_to_response('vulture/user_form.html', {'form': form, 'user' : request.user })

update_user = user_passes_test(lambda u: is_administrator(u), login_url='/logon/')(update_user)

def create_sql(request):
    manipulator = SQLAddManipulator()
    if request.POST:
        new_data = request.POST.copy()
        errors = manipulator.get_validation_errors(new_data)
        if not errors:
            manipulator.do_html2python(new_data)
            manipulator.save(new_data)
            return HttpResponseRedirect("/sql/")
    else:
        errors = new_data = {}
    form = forms.FormWrapper(manipulator, new_data, errors)
    return render_to_response('vulture/sql_form.html', {'form': form, 'user' : request.user})

create_sql = user_passes_test(lambda u: is_administrator(u), login_url='/logon/')(create_sql)


def update_sql(request, object_id):
    try:
        manipulator = SQLChangeManipulator()
        manipulator.id = object_id
    except SQL.DoesNotExist:
        raise Http404
    if request.POST:
        new_data = request.POST.copy()
        errors = manipulator.get_validation_errors(new_data)
        if not errors:
            manipulator.do_html2python(new_data)
            manipulator.save(new_data)
            return HttpResponseRedirect("/sql/")
    else:
        errors = {}
        sql = SQL.objects.get(name=object_id)
        new_data = { 'name' : sql.name, 'database' : sql.database, 'driver' : sql.driver, 'host' : sql.host, 'table' : sql.table,
                     'user' : sql.user, 'password' : sql.password, 'user_column' : sql.user_column, 'pass_column' : sql.pass_column, 'pass_algo' : sql.pass_algo,
                     'display_portal' : sql.display_portal }
    form = forms.FormWrapper(manipulator, new_data, errors)
    return render_to_response('vulture/sql_form.html', {'form': form, 'user' : request.user, 'sql' : sql})

update_sql = user_passes_test(lambda u: is_administrator(u), login_url='/logon/')(update_sql)


def create_ldap(request):
    manipulator = LDAPAddManipulator()
    if request.POST:
        new_data = request.POST.copy()
        errors = manipulator.get_validation_errors(new_data)
        if not errors:
            manipulator.do_html2python(new_data)
            manipulator.save(new_data)
            return HttpResponseRedirect("/ldap/")
    else:
        errors =  { }
        new_data = { 'port' : 389, 'protocol' : 2, 'user_filter' : '(|(objectclass=posixAccount)(objectclass=inetOrgPerson)(objectclass=person))',
                     'group_filter' : '(|(objectclass=posixGroup)(objectclass=group)(objectclass=groupofuniquenames))' }
    form = forms.FormWrapper(manipulator, new_data, errors)
    return render_to_response('vulture/ldap_form.html', {'form': form, 'user' : request.user})

create_ldap = user_passes_test(lambda u: is_administrator(u), login_url='/logon/')(create_ldap)

def update_ldap(request, object_id):
    try:
        manipulator = LDAPChangeManipulator()
        manipulator.id = object_id
    except LDAP.DoesNotExist:
        raise Http404
    if request.POST:
        new_data = request.POST.copy()
        errors = manipulator.get_validation_errors(new_data)
        if not errors:
            manipulator.do_html2python(new_data)
            manipulator.save(new_data)
            return HttpResponseRedirect("/ldap/")
    else:
        errors = {}
        ldap = LDAP.objects.get(name=object_id)
    form = forms.FormWrapper(manipulator, { 'name' : ldap.name, 'host' : ldap.host, 'port' : ldap.port, 'protocol' : ldap.protocol, 'scheme' : ldap.scheme,
                                            'base_dn' : ldap.base_dn, 'dn' : ldap.dn, 'password' : ldap.password, 'user_attr': ldap.user_attr,
                                            'group_attr' : ldap.group_attr, 'group_member' : ldap.group_member, 'user_filter': ldap.user_filter,
                                            'group_filter' : ldap.group_filter, 'group_scope':ldap.group_scope, 'user_scope': ldap.user_scope}, errors)
    return render_to_response('vulture/ldap_form.html', {'form': form, 'user' : request.user})

update_ldap = user_passes_test(lambda u: is_administrator(u), login_url='/logon/')(update_ldap)

def create_ssl(request):
    manipulator = SSLAddManipulator()
    if request.POST:
        new_data = request.POST.copy()
        errors = manipulator.get_validation_errors(new_data)
        if not errors:
            manipulator.do_html2python(new_data)
            manipulator.save(new_data)
            return HttpResponseRedirect("/ssl/")
    else:
        errors =  { }
        new_data = { }
    form = forms.FormWrapper(manipulator, new_data, errors)
    return render_to_response('vulture/ssl_form.html', {'form': form, 'user' : request.user})

create_ssl = user_passes_test(lambda u: is_administrator(u), login_url='/logon/')(create_ssl)

def update_ssl(request, object_id):
    try:
        manipulator = SSLChangeManipulator()
        manipulator.id = object_id
    except SSL.DoesNotExist:
        raise Http404
    if request.POST:
        new_data = request.POST.copy()
        errors = manipulator.get_validation_errors(new_data)
        if not errors:
            manipulator.do_html2python(new_data)
            manipulator.save(new_data)
            return HttpResponseRedirect("/ssl/")
    else:
        errors = {}
        ssl = SSL.objects.get(name=object_id)
        new_data = { 'name' : ssl.name, 'require' : ssl.require, 'crt' : ssl.crt }
    form = forms.FormWrapper(manipulator, new_data, errors)
    return render_to_response('vulture/ssl_form.html', {'form': form, 'user' : request.user})

update_ssl = user_passes_test(lambda u: is_administrator(u), login_url='/logon/')(update_ssl)

def create_acl(request):
    manipulator = ACLAddManipulator([], [], [], [])
    if request.POST:
        new_data = request.POST.copy()
        errors = manipulator.get_validation_errors(new_data)
        if not errors:
            manipulator.do_html2python(new_data)
            manipulator.save(new_data)
            if request.POST.get("send"):
                return HttpResponseRedirect("/acl/")
            else:
                return HttpResponseRedirect("/acl/"+str(manipulator.id)+"/")
    else:
        errors =  { }
        new_data = { }
    form = forms.FormWrapper(manipulator, new_data, errors)
    return render_to_response('vulture/acl_form.html', {'form': form, 'user' : request.user})

create_acl = user_passes_test(lambda u: is_administrator(u), login_url='/logon/')(create_acl)

def update_acl(request, object_id):
    try:
        user_ko = []
        group_ko = []
        group_ok = []
        user_ok = []
        acl = ACL.objects.get(name=object_id)
        for user in UserOK.objects.filter(acl=acl):
            user_ok.append([user.user,user.user])
        for group in GroupOK.objects.filter(acl=acl):
            group_ok.append([group.group,group.group])
        if acl.auth.type == 'sql':
            user_ko = SQL.objects.get(name=acl.auth).user_ko(user_ok)
        if acl.auth.type == 'ldap':
            user_ko = LDAP.objects.get(name=acl.auth).user_ko(user_ok)
            group_ko = LDAP.objects.get(name=acl.auth).group_ko(group_ok)
        manipulator = ACLChangeManipulator(user_ko, user_ok, group_ko, group_ok)
        manipulator.id = object_id
    except:
        pass
    if request.POST:
        new_data = request.POST.copy()
        errors = manipulator.get_validation_errors(new_data)
        if not errors:
            manipulator.do_html2python(new_data)
            manipulator.save(new_data)
            if request.POST.get("add_users"):
                for user in request.POST.getlist('user_ko'):
                    UserOK(acl=ACL.objects.get(name=object_id), user=user).save()
                return HttpResponseRedirect("/acl/"+object_id+"/")                
            if request.POST.get("del_users"):
                for user in request.POST.getlist('user_ok'):
                    UserOK.objects.get(acl=ACL.objects.get(name=object_id), user=user).delete()
                return HttpResponseRedirect("/acl/"+object_id+"/")                    
            if request.POST.get("add_groups"):
                for group in request.POST.getlist('group_ko'):
                    GroupOK(acl=ACL.objects.get(name=object_id), group=group).save()
                return HttpResponseRedirect("/acl/"+object_id+"/")                    
            if request.POST.get("del_groups"):
                for group in request.POST.getlist('group_ok'):
                    GroupOK.objects.get(acl=ACL.objects.get(name=object_id), group=group).delete()
                return HttpResponseRedirect("/acl/"+object_id+"/")
            if request.POST.get("send"):
                return HttpResponseRedirect("/acl/")
            else:
                UserOK.objects.filter(acl=object_id).delete()
                GroupOK.objects.filter(acl=object_id).delete()
                return HttpResponseRedirect("/acl/"+object_id+"/")
    else:
        errors = {}
        acl = ACL.objects.get(name=object_id)
        new_data = { 'name' : acl.name, 'auth' : acl.auth}
    form = forms.FormWrapper(manipulator, new_data, errors)
    return render_to_response('vulture/acl_form.html', {'form': form,
                                                        'user' : request.user, 'user_ko' : user_ko, 'user_ok' : user_ok,
                                                        'group_ko' : group_ko, 'group_ok' : group_ok })

update_acl = user_passes_test(lambda u: is_administrator(u), login_url='/logon/')(update_acl)

def delete_auth(request, model, post_delete_redirect,
        object_id=None, slug=None, slug_field=None, template_name=None,
        template_loader=loader, extra_context=None,
        login_required=False, context_processors=None, template_object_name='object'):

    if extra_context is None: extra_context = {}
    if login_required and not request.user.is_authenticated():
        return redirect_to_login(request.path)

    # Look up the object to be edited
    lookup_kwargs = {}
    if object_id:
        lookup_kwargs['%s__exact' % model._meta.pk.name] = object_id
    elif slug and slug_field:
        lookup_kwargs['%s__exact' % slug_field] = slug
    else:
        raise AttributeError("Generic delete view must be called with either an object_id or a slug/slug_field")
    try:
        object = model._default_manager.get(**lookup_kwargs)
    except ObjectDoesNotExist:
        raise Http404, "No %s found for %s" % (model._meta.app_label, lookup_kwargs)

    if request.method == 'POST':
        Auth.objects.get(id=object.name.id).delete()
        object.delete()
        if request.user.is_authenticated():
            request.user.message_set.create(message="The %s was deleted." % model._meta.verbose_name)
        return HttpResponseRedirect(post_delete_redirect)
    else:
        if not template_name:
            template_name = "%s/%s_confirm_delete.html" % (model._meta.app_label, model._meta.object_name.lower())
        t = template_loader.get_template(template_name)
        c = RequestContext(request, {
            template_object_name: object,
        }, context_processors)
        for key, value in extra_context.items():
            if callable(value):
                c[key] = value()
            else:
                c[key] = value
        response = HttpResponse(t.render(c))
        populate_xheaders(request, response, model, getattr(object, object._meta.pk.name))
        return response

delete_auth = user_passes_test(lambda u: is_administrator(u), login_url='/logon/')(delete_auth)

class PKCS12Manipulator(forms.Manipulator):
    def passphrase(self):
        characters = ('a','b','c','d','e','f','g','h','i','j','k','l','m',
                      'a','b','c','d','e','f','g','h','i','j','k','l','m',
                      'n','o','p','q','r','s','t','u','v','w','x','y','z',
                      'n','o','p','q','r','s','t','u','v','w','x','y','z',
                      'A','B','C','D','E','F','G','H','I','J','K','L','M',
                      'A','B','C','D','E','F','G','H','I','J','K','L','M',                      
                      'N','O','P','Q','R','S','T','U','V','W','X','Y','Z',
                      '0','1','2','3','4','5','6','7','8','9',
                      '!','@','#','$','%','^','&','*','=','?','+','-','_')

        i = 0
        passphrase = ''
        while i < 8 :
            passphrase = '%s%s' % (passphrase, choice(characters))
            i = i + 1
        return passphrase

class downloadPKCS12Manipulator(PKCS12Manipulator):
    def __init__(self):
        self.fields = (
            forms.TextField(field_name="passphrase"),
            )
    def pkcs12(self, passphrase):
        cert = Cert.objects.get(id=self.id)
        return cert.pkcs12(passphrase)

class sendPKCS12Manipulator(PKCS12Manipulator):
    def __init__(self):
        self.fields = (
            forms.TextField(field_name="mail"),
            forms.TextField(field_name="passphrase"),
            )
    def send(self, to, passphrase):
        cert = Cert.objects.get(id=self.id)
        return cert.send(to, passphrase)

class CertManipulator(forms.Manipulator):
    def __init__(self):
        profile_choices = []
        for name in CertProfile.objects.all():
            profile_choices.append((name, name))
        self.fields = (
            forms.SelectField(field_name="profile", is_required=True, choices=profile_choices),
            forms.TextField(field_name="cn", is_required=True, validator_list=[self.isUnique]),
            forms.TextField(field_name="country", is_required=True, maxlength=2),
            forms.TextField(field_name="organisation", is_required=True),
            forms.TextField(field_name="st", is_required=True),
            forms.EmailField(field_name="mail", is_required=True),
            forms.PasswordField(field_name="passphrase"),
            forms.TextField(field_name="valid_until"),
            )
    def isUnique(self, field_data, all_data):
        if Cert.objects.filter(cn=field_data).count():
            raise validators.ValidationError("Certificat with name %s already exists" % field_data)
    def save(self, new_data):
        cert = Cert(cn=new_data['cn'], mail=new_data['mail'], profile=CertProfile.objects.get(name=new_data['profile']), organisation=new_data['organisation'], st=new_data['st'], country=new_data['country'])
        cert.valid_until = datetime.datetime.fromtimestamp(time.mktime(time.strptime(new_data['valid_until'],"%d/%m/%Y")))
        cert.save()
        cert.sign()
        cert.save()

def create_cert(request):
    manipulator = CertManipulator()
    if request.POST:
        new_data = request.POST.copy()
        errors = manipulator.get_validation_errors(new_data)
        if not errors:
            manipulator.do_html2python(new_data)
            manipulator.save(new_data)
            return HttpResponseRedirect("/pki/")
    else:
        errors =  { }
        valid_until = datetime.datetime.now() + datetime.timedelta(days=365)
        new_data = { 'valid_until' : valid_until.strftime("%d/%m/%Y"), 'country' : 'FR' }
    form = forms.FormWrapper(manipulator, new_data, errors)
    return render_to_response('vulture/cert_form.html', {'form': form, 'user' : request.user, 'display_profile' : CertProfile.objects.count() > 1, 'administrator' : is_administrator(request.user)})

create_cert = user_passes_test(lambda u: is_pki_op(u), login_url='/logon/')(create_cert)

class CertChangeManipulator(CertManipulator):        
    def isUnique(self, field_data, all_data):
        if Cert.objects.filter(cn=field_data).exclude(id=self.id).count():
            raise validators.ValidationError("A certificat already exists with that CN")
    def save(self, new_data):
        cert = Cert.objects.get(id=self.id)
        cert.cn = new_data['cn']
        cert.mail = new_data['mail']
        cert.organisation = new_data['organisation']
        cert.st = new_data['st']
        cert.country = new_data['country']
        cert.valid_until = datetime.datetime.fromtimestamp(time.mktime(time.strptime(new_data['valid_until'],"%d/%m/%Y")))
        cert.save()
        try:
            cert.save()
            cert.sign()
            cert.save()
        except:
            cert.delete()

def update_cert(request, object_id):
    try:
        manipulator = CertChangeManipulator()
        manipulator.id = object_id
    except Cert.DoesNotExist:
        raise Http404
    if request.POST:
        new_data = request.POST.copy()
        errors = manipulator.get_validation_errors(new_data)
        if not errors:
            manipulator.do_html2python(new_data)
            manipulator.save(new_data)
            return HttpResponseRedirect("/pki/")
    cert = Cert.objects.get(id=object_id)
    form = forms.FormWrapper(manipulator, { 'cn' : cert.cn, 'mail' : cert.mail, 'organisation' : cert.organisation, 'st': cert.st, 'country' : cert.country, 'valid_until' : cert.valid_until.strftime("%d/%m/%Y") }, {})
    return render_to_response('vulture/cert_update_form.html', {'form': form, 'user' : request.user, 'administrator' : is_administrator(request.user) })

update_cert = user_passes_test(lambda u: is_pki_op(u), login_url='/logon/')(update_cert)

def download_p12(request, object_id):
    try:
        manipulator = downloadPKCS12Manipulator()
        manipulator.id = object_id
    except Cert.DoesNotExist:
        raise Http404
    if request.POST:
        new_data = request.POST.copy()
        errors = manipulator.get_validation_errors(new_data)
        if not errors:
            manipulator.do_html2python(new_data)
            response = HttpResponse(mimetype='application/octet-stream')
            response['Content-Disposition'] = 'attachment; filename=' + string.replace(Cert.objects.get(id=object_id).cn, ' ', '_') + '.p12'
            response.write(manipulator.pkcs12(new_data['passphrase']))
            return response
    else:
        errors = {}
        cert = Cert.objects.get(id=object_id)
        new_data = { 'mail' : cert.mail }
    form = forms.FormWrapper(manipulator, new_data, errors)
    new_data = { 'passphrase' : manipulator.passphrase()}
    form = forms.FormWrapper(manipulator, new_data, errors)
    return render_to_response('vulture/download_p12.html', {'form': form, 'user' : request.user, 'administrator' : is_administrator(request.user) })

download_p12 = user_passes_test(lambda u: is_pki_op(u), login_url='/logon/')(download_p12)

def send_p12(request, object_id):
    try:
        manipulator = sendPKCS12Manipulator()
        manipulator.id = object_id
    except Cert.DoesNotExist:
        raise Http404
    if request.POST:
        new_data = request.POST.copy()
        errors = manipulator.get_validation_errors(new_data)
        if not errors:
            manipulator.send(new_data['mail'], new_data['passphrase'])
            return HttpResponseRedirect('/pki/0/')
    else:
        errors = {}
        cert = Cert.objects.get(id=object_id)
        new_data = { 'passphrase' : manipulator.passphrase(), 'mail' : cert.mail }
    form = forms.FormWrapper(manipulator, new_data, errors)
    return render_to_response('vulture/send_p12.html', {'form': form, 'user' : request.user, 'administrator' : is_administrator(request.user) })

send_p12 = user_passes_test(lambda u: is_pki_op(u), login_url='/logon/')(send_p12)

def revoke(request, object_id):
    try:
        cert = Cert.objects.get(id=object_id)
    except Cert.DoesNotExist:
        return HttpResponseRedirect("/pki/")
    if not cert.revoked:
        cert.revoked = datetime.datetime.now()
    else:
        cert.revoked = None
    cert.save()
    crl = crypto.CRL()
    for cert in Cert.objects.exclude(revoked__isnull=True):
        print cert.revoked.strftime("%y%m%d%H%M%SZ")
        crl.make_revoked(cert.revoked.strftime("%y%m%d%H%M%SZ"), ("%s" % cert.id))
    open("%s" % cert.profile.crl_path, "w").write(crypto.dump_crl(crl, crypto.load_certificate(crypto.FILETYPE_PEM, cert.profile.ca_cert), crypto.load_privatekey(crypto.FILETYPE_PEM, cert.profile.ca_key)))
    return HttpResponseRedirect("/pki/")

revoke = user_passes_test(lambda u: is_pki_op(u), login_url='/logon/')(revoke)

def list_cert_page(request, page_id):
    if request.POST:
        request.session['search'] = request.POST.get('search')
        request.session['expire'] = ''
        request.session['profil'] = ''
    list = Cert.objects
    if request.POST.get('profil'):
        request.session['profil'] = int(request.POST.get('profil'))
    if request.session.get('profil'):
        list = list.filter(profile=request.session.get('profil'))
    if request.POST.get('expire'):
        request.session['expire'] = int(request.POST.get('expire'))
    if request.session.get('expire'):
        list = list.filter(valid_until__lt=datetime.datetime.now()+datetime.timedelta())
    paginator = ObjectPaginator(list.filter(Q(cn__icontains=request.session.get('search')) | Q(mail__icontains=request.session.get('search'))), 30)
    list = None
    try:
        list = paginator.get_page(page_id)
    except:
        pass
    profile_choices = []
    for p in CertProfile.objects.all():
        profile_choices.append(p)
    return render_to_response('vulture/cert_list.html', {'profil' : request.session.get('profil'), 'expire' : request.session.get('expire'), 'profile_choices' : profile_choices, 'object_list': list, 'user' : request.user, 'search' : request.session.get('search'), 'forward' : paginator.has_next_page(int(page_id)), 'back' : paginator.has_previous_page(int(page_id)), 'page_id_back' : int(page_id) - 1, 'page_id_forward' : int(page_id) + 1, 'administrator' : is_administrator(request.user) })

list_cert_page = user_passes_test(lambda u: is_pki_op(u), login_url='/logon/')(list_cert_page)

def list_cert_dump(request):
    return render_to_response('vulture/cert_list_dump.html', {'object_list' : Cert.objects.all() })

list_cert_dump = user_passes_test(lambda u: is_pki_op(u), login_url='/logon/')(list_cert_dump)

def ca_dump(request):
    return render_to_response('vulture/ca_dump.html', {'object_list' : CertProfile.objects.all() })

ca_dump = user_passes_test(lambda u: is_pki_op(u), login_url='/logon/')(ca_dump)

def list_cert(request):
    return HttpResponseRedirect("/pki/0/")

list_cert = user_passes_test(lambda u: is_pki_op(u), login_url='/logon/')(list_cert)

def update_app(request, object_id):    
    try:
        manipulator = App.ChangeManipulator(object_id)
        manipulator.id = object_id
    except App.DoesNotExist:
        raise Http404
    if request.POST:
        new_data = request.POST.copy()
        errors = manipulator.get_validation_errors(new_data)
        if not errors:
            manipulator.do_html2python(new_data)
            manipulator.save(new_data)
            return HttpResponseRedirect("/app/")
    else:
        errors = {}
        new_data = manipulator.flatten_data()
    form = forms.FormWrapper(manipulator, new_data, errors)
    return render_to_response('vulture/app_form.html', {'form': form, 'user' : request.user, 'headers' : Header.objects.filter(app=object_id), 'administrator' : is_administrator(request.user) })

update_app = user_passes_test(lambda u: is_administrator(u), login_url='/logon/')(update_app)
