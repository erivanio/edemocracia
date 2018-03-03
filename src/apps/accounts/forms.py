from django.contrib.auth.tokens import default_token_generator
from django.contrib.sites.shortcuts import get_current_site
from django.utils.encoding import force_bytes
from django.utils.http import urlsafe_base64_encode
from django import forms
from django.contrib.auth.models import User
from django.utils.safestring import mark_safe
from django.utils.translation import ugettext_lazy as _
from apps.accounts.models import UserProfile
import requests


class SignUpAjaxForm(forms.ModelForm):
    uf = forms.CharField(required=False)
    country = forms.CharField(required=False)
    birthdate = forms.DateField(required=False)
    gender = forms.CharField(required=False)

    required = ('email', 'password', 'first_name')

    error_messages = {
        'empty_email': _('This field is required.'),
        'exists_email': _('There is already a user registered with'
                          ' this email.'),
        'length_password': _('The password must be at least 6'
                             ' characters long.'),
        'empty_uf_country': _('The state or country fields must be filled in.'),
        'empty_uf': _('Select a UF, if you are a foreigner, '
                      'click on I am a foreigner'),
        'empty_country': _('Select a country, if you are not a foreigner,'
                           ' click on "I am Brazilian".'),
    }

    class Meta:
        fields = ('email', 'password', 'first_name')
        model = User

    def clean(self):
        cleaned_data = super(SignUpAjaxForm, self).clean()
        uf = cleaned_data.get("uf", None)
        country = cleaned_data.get("country", None)

        if not uf and not country:
            self.add_error('uf', mark_safe(
                self.error_messages.get('empty_uf')))
            self.add_error('country', mark_safe(
                self.error_messages.get('empty_country')))
            raise forms.ValidationError(mark_safe(
                self.error_messages.get('empty_uf_country')))

        return cleaned_data

    def clean_password(self):
        password = self.cleaned_data.get("password", None)

        if len(password) < 6:
            raise forms.ValidationError(
                mark_safe(self.error_messages.get('length_password')))

        return password

    def clean_email(self):
        email = self.cleaned_data.get("email", None)
        users = User.objects.filter(email=email)

        if not email:
            raise forms.ValidationError(
                mark_safe(self.error_messages.get('empty_email')))

        if users.exists():
            raise forms.ValidationError(
                mark_safe(self.error_messages.get('exists_email')))

        return email

    def save(self, commit=True):
        user = super().save(commit=False)
        user.set_password(self.cleaned_data["password"])
        if commit:
            user.save()
        return user


class UserProfileForm(forms.ModelForm):
    first_name = forms.CharField(required=False)
    last_name = forms.CharField(required=False)

    def __init__(self, *args, **kwargs):
        super(UserProfileForm, self).__init__(*args, **kwargs)
        self.fields['first_name'].initial = kwargs['instance'].user.first_name
        self.fields['last_name'].initial = kwargs['instance'].user.last_name
        for field_name in self.fields:
            field = self.fields.get(field_name)
            if field and isinstance(field, forms.TypedChoiceField):
                field.choices = field.choices[1:]

    class Meta:
        fields = ('gender', 'uf', 'birthdate', 'first_name', 'last_name',
                  'avatar')
        model = UserProfile

    def save(self, commit=True):
        instance = super(UserProfileForm, self).save(commit=False)
        instance.save()
        instance.user.first_name = self.cleaned_data['first_name']
        instance.user.last_name = self.cleaned_data['last_name']
        if commit:
            instance.user.save()
        return instance


class CustomPasswordResetForm(forms.Form):
    email = forms.EmailField(label=_("Email"), max_length=254)

    def get_users(self, email):
        active_users = User._default_manager.filter(**{
            '%s__iexact' % User.get_email_field_name(): email,
            'is_active': True,
        })
        return (u for u in active_users if u.has_usable_password())

    def save(self, domain_override=None,
             subject_template_name='registration/password_reset_subject.txt',
             email_template_name='registration/password_reset_email.html',
             use_https=False, token_generator=default_token_generator,
             from_email=None, request=None, html_email_template_name=None,
             extra_email_context=None):
        email = self.cleaned_data["email"]
        for user in self.get_users(email):
            if not domain_override:
                current_site = get_current_site(request)
                site_name = current_site.name
                domain = current_site.domain
            else:
                site_name = domain = domain_override
            context = {
                'email': email,
                'domain': domain,
                'site_name': site_name,
                'uid': urlsafe_base64_encode(force_bytes(user.pk)).decode(),
                'user': user,
                'token': token_generator.make_token(user),
                'protocol': 'https' if use_https else 'http',
                **(extra_email_context or {}),
            }

            import ipdb; ipdb.set_trace()
            payload = {'nome': user.first_name,
                       'link': domain + '/accounts/password/reset/confirm/' + context['uid'] + '/' + context['token'] + '/',
                       'email': email}

            requests.post("http://example.com/", data=payload)  # to send email
