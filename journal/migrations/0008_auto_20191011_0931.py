# Generated by Django 2.2.4 on 2019-10-11 09:31

from django.db import migrations, models
import django.db.models.deletion



class Migration(migrations.Migration):
    dependencies = [
        ('journal', '0007_studentattendancetype_name'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='lesson',
            name='date',
        ),
        migrations.AddField(
            model_name='lesson',
            name='attendance',
            field=models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.DO_NOTHING,
                                    to='journal.Attendance'),
        ),
    ]
