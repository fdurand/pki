from django.forms import widgets
from rest_framework import serializers
from pki.models import *

class CertProfileSerializer(serializers.ModelSerializer):
    class Meta:
        model = CertProfile

class CertSerializer(serializers.ModelSerializer):
    profile = serializers.SlugRelatedField(slug_field = 'name')

    class Meta:
        model = Cert
        fields = ('cn', 'mail', 'st', 'organisation', 'country', 'x509', 'profile')


