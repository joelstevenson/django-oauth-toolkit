# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('oauth2_provider', '0004_auto_20160419_2208'),
    ]

    operations = [
        migrations.AddField(
            model_name='accesstoken',
            name='claims',
            field=models.TextField(blank=True),
        ),
        migrations.AddField(
            model_name='grant',
            name='claims',
            field=models.TextField(blank=True),
        ),
        migrations.AlterField(
            model_name='application',
            name='authorization_grant_type',
            field=models.CharField(max_length=32, choices=[('authorization-code', 'Authorization code'), ('implicit', 'Implicit'), ('password', 'Resource owner password-based'), ('client-credentials', 'Client credentials'), ('openid', 'OpenID Connect')]),
        ),
    ]
