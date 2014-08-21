from django.core.urlresolvers import reverse_lazy
from django.views.generic import RedirectView
from django.conf.urls import patterns, include, url

from django.contrib import admin
admin.autodiscover()
from pki import views

urlpatterns = patterns('',
    # Examples:
    url(r'^admin/', include(admin.site.urls)),
    url(r'^$', 'pki.views.logon'),
    url(r'^pki', include('pki.urls')),
    url(r'^logon/$',  'pki.views.logon'),
    url(r'^logout/$', 'pki.views.disconnect'),
    url(r'^users/(?P<pk>\d+)/del/$',           views.delete_user.as_view(), name='user_delete'),
    url(r'^users/(?P<pk>\d+)/$',               views.update_user.as_view(), name='user_update'),
    url(r'^users/new/$',                       views.register, name='user_add'),
    url(r'^users/$',                           views.list_user.as_view(), name='user_list'),
)
