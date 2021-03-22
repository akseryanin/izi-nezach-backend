from django.http import HttpResponseRedirect
import json

from api.forms import PenaltyForm
from journal.models import Penalty, Student, Attendance

def add_penalty(request):
    if request.method == 'POST':
        attrs = request.POST
        if len(request.POST) == 0:
            attrs = json.loads(request.body)
        form = PenaltyForm(attrs)
        data = form.data
        print("form=", data)
        student = Student.objects.filter(pk=data['student_id']).first()
        attendance = Attendance.objects.get(id=data['attendance_id'])
        penalty = Penalty(
            type=data['penalty_type'],
            comment=data['comment'],
            student=student,
            attendance=attendance,
        )
        penalty.save()
    return HttpResponseRedirect(request.META.get('HTTP_REFERER', '/'))
