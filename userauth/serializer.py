from django.contrib.auth.models import User, Group
from rest_framework.validators import UniqueValidator
from rest_framework import serializers
from django.contrib.auth.password_validation import validate_password
from .models import Profile

class RegisterSerializer(serializers.ModelSerializer):
    email = serializers.EmailField(
        required=True,
        validators=[UniqueValidator(queryset=User.objects.all())]
    )
    password = serializers.CharField(write_only=True, required=True, validators=[validate_password])
    user_type = serializers.ChoiceField(choices=[('buyer', 'Buyer'), ('seller', 'Seller')], required=True)

    class Meta:
        model = User
        fields = ('username', 'email', 'password', 'confirm_password', 'user_type')
    def validate(self, attrs):
        if User.objects.filter(email=attrs['email']).exists():
            raise serializers.ValidationError({"email": "This email is already in use."})
        if User.objects.filter(username=attrs['username']).exists():
            raise serializers.ValidationError({"username": "This username is already taken."})
        return attrs
    def create(self, validated_data):
        user_type = validated_data.pop('user_type') 
        password = validated_data.pop('password'),
        user = User(
            username=validated_data['username'],
            email=validated_data['email'],
        )
        user.set_password(password)
        user.save()
        if user_type == 'seller':
            seller_group, _ = Group.objects.get_or_create(name='Seller')
            user.groups.add(seller_group)
        elif user_type == 'buyer':
            buyer_group, _ = Group.objects.get_or_create(name='Buyer')
            user.groups.add(buyer_group)
        elif user.user_type == "admin":
            admin_group, _ = Group.objects.get_or_create(name='Admin')
            user.groups.add(admin_group)
        return User.objects.create_user(**validated_data)
class ProfileSerializer(serializers.ModelSerializer):
    class Meta:
        model = Profile
        fields = ["id", "name", "bio", "picture"]

class ResetPasswordEmailRequestSerializer(serializers.Serializer):
    email = serializers.EmailField(min_length=2)

    redirect_url = serializers.CharField(max_length=500, required=False, read_only=True)

    class Meta:
        fields = ['email']