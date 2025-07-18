# Generated by Django 5.2.3 on 2025-07-07 13:22

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('recipes', '0002_recipe_author_recipe_category'),
    ]

    operations = [
        migrations.AlterField(
            model_name='recipe',
            name='cover',
            field=models.ImageField(blank=True, default='', upload_to='recipes/covers/%Y/%m/%d/'),
        ),
        migrations.AlterField(
            model_name='recipe',
            name='slug',
            field=models.SlugField(unique=True),
        ),
    ]
