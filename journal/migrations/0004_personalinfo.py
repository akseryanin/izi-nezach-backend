# Generated by Django 2.2.4 on 2019-09-27 08:40

from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('journal', '0003_auto_20190927_0828'),
    ]

    operations = [
        migrations.CreateModel(
            name='PersonalInfo',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('passport_code', models.CharField(blank=True, max_length=4)),
                ('passport_number', models.CharField(blank=True, max_length=6)),
                ('passport_issued', models.CharField(blank=True, max_length=6)),
                ('address', models.CharField(blank=True, max_length=512)),
                ('birth_date', models.DateField(blank=True, null=True)),
                ('characteristic', models.TextField(blank=True)),
                ('student', models.ForeignKey(on_delete=django.db.models.deletion.DO_NOTHING, to='journal.Student')),
            ],
            options={
                'db_table': 'student_info',
                'managed': True,
            },
        ),
    ]