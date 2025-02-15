# Generated by Django 5.1.6 on 2025-02-12 12:39

import accounts.utils
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('accounts', '0003_alter_nexususer_profile_image'),
    ]

    operations = [
        migrations.AlterField(
            model_name='nexususer',
            name='profile_image',
            field=models.ImageField(default='user_profile_images/default_profile.jpg', max_length=300, upload_to=accounts.utils.get_NexusUser_profile_image_upload_path),
        ),
    ]
