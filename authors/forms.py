import re

from django import forms
from django.contrib.auth.models import User
from django.core.exceptions import ValidationError

def add_attr(field, attr_name, attr_val):
  existing_attr = field.widget.attrs.get(attr_name, '')
  field.widget.attrs[attr_name] = f'{existing_attr} {attr_val}'.strip()

def add_placeholder(field, placeholder_val):
  add_attr(field, 'placeholder', placeholder_val)

def strong_password(password):
    regex = re.compile(r'^(?=.*[a-z])(?=.*[A-Z])(?=.*[0-9]).{8,}$')
    if not regex.match(password):
        raise ValidationError((
            'Password must have at least one uppercase letter, '
            'one lowercase letter and one number. The length should be '
            'at least 8 characters.'
        ),
            validators=[strong_password],
            code='invalid'
        )

class RegisterForm(forms.ModelForm):
  password2 = forms.CharField(
        label='Password2',
        required=True,
        widget=forms.PasswordInput(attrs={
            'placeholder': 'Repeat your password here'
        })
    )
  def __init__(self, *args, **kwargs):
    super().__init__(*args, **kwargs)
    add_placeholder(self.fields['username'], 'Your Username')
    add_placeholder(self.fields['email'], 'Your E-mail')
    add_placeholder(self.fields['first_name'], 'Ex.: John')
    add_placeholder(self.fields['last_name'], 'Ex.: Doe')
  class Meta:
    model = User
    fields = ['first_name', 'last_name', 'username', 'email', 'password', 'password2']
#   exclude = 
    labels = {
      'username': 'Username',
      'first_name': 'First name',
      'last_name': 'Last name',
      'email': 'E-mail',
      'password': 'Password',
      'password2': 'Repeat Password'
    }
    help_texts = {
      'email': 'The e-mail must be valid.'
    }
    error_messages = {
      'username': {
        'required': 'This field must not be empty'
      }
    }
    widgets = {
      'first_name': forms.TextInput(attrs={
        'placeholder': "Type your username here"
      }),
      'password': forms.PasswordInput(attrs={
        'placeholder': "Type your password here"
      })
    }

  def clean_password(self):
    data = self.cleaned_data.get('password')
    
    if 'atenção' in data:
      raise ValidationError('Não digite %(value)s no campo password', code='invalid', params={ 'value': 'atenção' })
    
    return data
  
  def clean(self):
      cleaned_data = super().clean()

      password = cleaned_data.get('password')
      password2 = cleaned_data.get('password2')

      if password != password2:
          password_confirmation_error = ValidationError(
            'Password and password2 must be equal',
            code='invalid'
          )
          raise ValidationError({
            'password': password_confirmation_error,
            'password2': [
                  password_confirmation_error,
                ],
            })