from django.http import HttpResponseRedirect
import json

from api.forms import DutyForm
from journal.models import Duty, Student, Attendance


def add_duty(request):
    if request.method == 'POST':
        attrs = request.POST
        if len(request.POST) == 0:
            attrs = json.loads(request.body)
        form = DutyForm(attrs)
        data = form.data
        print("form=", data)
        student = Student.objects.filter(pk=data['student_id']).first()
        attendance = Attendance.objects.get(id=data['attendance_id'])
        duty = Duty(
            type=data['duty_type'],
            comment=data['comment'],
            student=student,
            attendance=attendance,
            mark=data['mark']
        )
        duty.save()
    return HttpResponseRedirect(request.META.get('HTTP_REFERER', '/'))
