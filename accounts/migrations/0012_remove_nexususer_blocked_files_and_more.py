# Generated by Django 5.1.6 on 2025-03-06 07:49

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('accounts', '0011_alter_nexususer_options_nexususer_disliked_files_and_more'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='nexususer',
            name='blocked_files',
        ),
        migrations.RemoveField(
            model_name='nexususer',
            name='disliked_files',
        ),
        migrations.RemoveField(
            model_name='nexususer',
            name='liked_files',
        ),
    ]
