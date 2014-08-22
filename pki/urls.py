from django.contrib.auth.decorators import login_required
from django.conf.urls import patterns, include, url

from pki import views

urlpatterns = patterns('',
    url(r'^/$',                               login_required(views.list_cert.as_view(),login_url='/logon/'), name='index'),
    url(r'/profile/(?P<pk>\d+)/del/$',        login_required(views.delete_cert_profile.as_view(),login_url='/logon/'), name='profile_delete'),
    url(r'/profile/(?P<pk>\d+)/$',            login_required(views.update_cert_profile.as_view(),login_url='/logon/'), name='profile_update'),
    url(r'/profile/new/$',                    login_required(views.create_cert_profile.as_view(),login_url='/logon/'), name='profile_add'),
    url(r'/profile/$',                        login_required(views.list_cert_profile.as_view(),login_url='/logon/'), name='profile_list'),
    url(r'/cert/(?P<pk>\d+)/del/$',           login_required(views.delete_cert.as_view(),login_url='/logon/'), name='cert_delete'),
    url(r'/cert/(?P<pk>\d+)/sign/$',          login_required(views.sign_cert,login_url='/logon/'), name='cert_sign'),
    url(r'/cert/(?P<pk>\d+)/revoke/$',        login_required(views.revoke_cert.as_view(),login_url='/logon/'), name='cert_revoke'),
    url(r'/cert/(?P<pk>\d+)/download/$',      login_required(views.download_cert,login_url='/logon/'), name='cert_download'),
    url(r'/cert/(?P<pk>\d+)/send/$',          login_required(views.send_cert,login_url='/logon/'), name='cert_send'),
    url(r'/cert/(?P<pk>\d+)/$',               login_required(views.update_cert.as_view(),login_url='/logon/'), name='cert_update'),
    url(r'/cert/new/$',                       login_required(views.create_cert.as_view(),login_url='/logon/'), name='cert_add'),
    url(r'/cert/rest/(?P<pk>[0-9]+)/$',       views.cert_detail.as_view()),
    url(r'/cert/restapi/(?P<pk>\w+)/$',       views.cert_list.as_view()),
    url(r'/cert/$',                           login_required(views.list_cert.as_view(),login_url='/logon/'), name='cert_list'),
    url(r'/ca/(?P<pk>\d+)/del/$',             login_required(views.delete_ca.as_view(),login_url='/logon/'), name='ca_delete'),
    url(r'/ca/(?P<pk>\d+)/sign/$',            login_required(views.sign_ca,login_url='/logon/'), name='ca_sign'),
    url(r'/ca/(?P<pk>\d+)/$',                 login_required(views.update_ca.as_view(),login_url='/logon/'), name='ca_update'),
    url(r'/ca/new/$',                         login_required(views.create_ca.as_view(),login_url='/logon/'), name='ca_add'),
    url(r'/ca/$',                             login_required(views.list_ca.as_view(),login_url='/logon/'), name='ca_list'),
    url(r'/ocsp/$',                           views.ocsp_server, name='ocsp'),
    url(r'/enrol/$',                          views.certWizard.as_view()),
    url(r'/rest/(?P<pk>\d+)/del/$',           login_required(views.delete_rest.as_view(),login_url='/logon/'), name='rest_delete'),
    url(r'/rest/(?P<pk>\d+)/$',               login_required(views.update_rest.as_view(),login_url='/logon/'), name='rest_update'),
    url(r'/rest/new/$',                       login_required(views.create_rest.as_view(),login_url='/logon/'), name='rest_add'),
    url(r'/rest/$',                           login_required(views.list_rest.as_view(),login_url='/logon/'), name='rest_list'),
)
