# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('oauth2_provider', '0003_auto_20160316_1503'),
    ]

    operations = [
        migrations.AddField(
            model_name='grant',
            name='acr',
            field=models.CharField(max_length=255, null=True),
        ),
        migrations.AddField(
            model_name='grant',
            name='max_age',
            field=models.SmallIntegerField(null=True),
        ),
    ]
