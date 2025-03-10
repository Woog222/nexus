# Generated by Django 5.1.6 on 2025-03-05 08:37

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('accounts', '0009_nexususer_banned_files_nexususerrelation_and_more'),
        ('engine', '0008_alter_nexusfile_options'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='nexususer',
            name='banned_files',
        ),
        migrations.AddField(
            model_name='nexususer',
            name='blocked_files',
            field=models.ManyToManyField(related_name='blocked_users', to='engine.nexusfile'),
        ),
    ]
