from django import forms
from django.core.exceptions import ValidationError
from journal.models import Duty


class LessonForm(forms.Form):
    name = forms.CharField(label='Название', max_length=100)
    date = forms.CharField(label='Дата', max_length=100)
    subject_id = forms.IntegerField(label='Дисциплина')
    squad_code = forms.CharField(label='Взвод', max_length=100)


class PenaltyForm(forms.Form):
    student_id = forms.IntegerField(label="Студент")
    comment = forms.CharField(label='Комментарий', max_length=100)
    attendance_id = forms.IntegerField(label='День посещения')
    penalty_type = forms.CharField(label="Статус")


class NewAttendanceForm(forms.Form):
    squad_code = forms.CharField(label="Взвод", max_length=4)
    date = forms.DateField(label='Дата')


class SetAttendanceStatusForm(forms.Form):
    student_id = forms.IntegerField(label="Студент")
    attendance_id = forms.IntegerField(label="Записка")
    attendance_type = forms.IntegerField(label="Статус")


class DutyForm(forms.Form):
    student_id = forms.IntegerField(label="Студент")
    comment = forms.CharField(label='Комментарий', max_length=100)
    attendance_id = forms.IntegerField(label='День посещения')
    duty_type = forms.CharField(label="Вид")
    mark = forms.IntegerField(label="Оценка")

    def clean_mark(self):
        mark = self.cleaned_data['mark']
        if mark < 1 or mark > 5:
            raise ValidationError('Invalid mark value', code='invalid')
        return mark


class NewEventForm(forms.Form):
    name = forms.CharField(label='Название', max_length=30)
    date = forms.DateField(label='Дата')


class SetEventForm(forms.Form):
    student_id = forms.IntegerField(label="Студент")
    event_id = forms.IntegerField(label='Событие')
