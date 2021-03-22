import datetime as dt

from django.db import IntegrityError
from django.shortcuts import render
from django.http import HttpResponseRedirect

from api.forms import NewAttendanceForm, SetAttendanceStatusForm
from journal.models import Squad, Lesson, Attendance, Student, StudentAttendance, Mark
from journal.managers.context import with_context
from journal.constants import *
from journal import constants



def add_attendance(request):
    if request.method == 'POST':
        form = NewAttendanceForm(request.POST)
        squad_code = form.data["squad_code"]
        date = form.data.get("date")
        date_str = dt.datetime.strptime(date, '%d-%m-%Y')
        # todo constants
        present = constants.ATTENDANCE_TYPE_PRESENT
        
        squad = Squad.objects.filter(code=squad_code)[0]
        att = Attendance(
            date=date_str,
            squad=squad,
        )
        try:
            att.save()
        except IntegrityError:
            return render(
                request,
                "journal/attendance.html",
                with_context({
                    "error": f"Для взвода {squad_code} уже существует строевая записка на {date_str}"
                }))

        students = Student.objects.filter(squad_id=squad.id)
        for student in students:
            val = StudentAttendance(
                student=student,
                value=present.value
            )
            val.save()
            att.students.add(val)
            pass

    return HttpResponseRedirect(request.META.get('HTTP_REFERER', '/'))



def set_attendance(request):
    if request.method == 'POST':
        form = SetAttendanceStatusForm(request.POST)
        data = form.data
        student_id = data["student_id"]
        att_id = data["attendance_id"]
        # todo validate
        new_value = data["attendance_type"]

        att = Attendance.objects.get(id=att_id)

        student_att: StudentAttendance = StudentAttendance.objects.get(student_id=student_id, attendance=att)

        prev_value = student_att.value

        student_att.value = new_value
        student_att.save()
        if new_value in (ATTENDANCE_TYPE_TRUANT.value, ATTENDANCE_TYPE_ABSENT.value, ATTENDANCE_TYPE_DUTY.value):
            # remove all marks for this attendance
            for m in Mark.objects.filter(student_id=student_id, lesson__attendance=att):
                m.delete()

    return HttpResponseRedirect(request.META.get('HTTP_REFERER', '/'))
