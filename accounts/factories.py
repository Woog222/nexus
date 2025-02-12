# accounts/factories.py
import factory
from .models import NexusUser

class NexusUserFactory(factory.django.DjangoModelFactory):
    class Meta:
        model = NexusUser

    user_id = factory.Faker("uuid4")
    user_name = factory.Faker("name")
    email = factory.Faker("email")
    profile_image = factory.django.ImageField(filename="profile.jpg")