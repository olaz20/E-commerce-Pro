# Generated by Django 5.1.2 on 2024-12-10 21:25

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('store', '0001_initial'),
    ]

    operations = [
        migrations.AlterField(
            model_name='order',
            name='tx_ref',
            field=models.CharField(blank=True, max_length=100, null=True),
        ),
    ]