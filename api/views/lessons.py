import datetime as dt

from django.http import HttpResponseRedirect

from api.forms import LessonForm
from journal.models import Squad, Lesson, StudentAttendance, Mark, Exam


def add_lesson(request):
    print(request)
    if request.method == 'POST':
        # create a form instance and populate it with data from the request:
        form = LessonForm(request.POST)
        data = form.data
        # squad = Squad.objects.filter(code=data["squad_code"])[0]
        # print("form=", form.data['date'], form.data['name'])
        print("form=", form.data)
        lesson = Lesson(
            name=data["name"],
            subject_id=data["subject_id"],
            # squad=squad,
            attendance_id=data["attendance_id"]
        )
        ex = data.get("exam_id")
        print('exam=', ex)
        if ex:
            lesson.exam = Exam.objects.get(id=ex)
        lesson.save()

        # att = lesson.attendance
        # for s in lesson.attendance.students.all():
        #     s: StudentAttendance = s
        #     if s.value == "truant":
        #         val = -1
        #     elif s.value == "absent":
        #         val = -2
        #     elif s.value == "duty":
        #         val = -3
        #     else:
        #         continue
        #     m = Mark(
        #         student=s.student,
        #         val=val,
        #         lesson=lesson,
        #     )
        #     m.save()

        print(request.build_absolute_uri())  # Keeps query parameters

        print(request.get_full_path())  # Keeps query parameters
    # return HttpResponseRedirect("")
    return HttpResponseRedirect(request.META.get('HTTP_REFERER', '/'))
