import json

from django.http import HttpResponse
from datetime import date
from api.models import rMark
from journal.models import Mark, UserExtension, Lesson



def add_mark(request):
    value2marks = {
        '1': 1,
        '2': 2,
        '3': 3,
        '4': 4,
        '5': 5,
        'п': -1,
        'у': -2,
        'н': -3,
    }

    m = Mark()
    d = json.loads(request.body)
    lesson = Lesson.objects.get(id=d["lesson_id"])

    user = request.user
    try:
        ext = UserExtension.objects.get(user=user)
    except UserExtension.DoesNotExist:
        ext = None
    if ext and lesson:
        if not ext.squads.filter(userextension__squads__code=lesson.attendance.squad.code).exists():
            return HttpResponse(json.dumps({
                "error": "Этот пользователь не может изменять и создавать оценки для данного взвода",
            }))

        if ext.date_limit and lesson.attendance.date != date.today():
            return HttpResponse(json.dumps({
                "error": "Этот пользователь может изменять оценки только на текущую дату",
            }))

    req = rMark(
        value=value2marks.get(d["value"].lower()),
        id=d["mark_id"],
        student_id=d["student_id"],
    )

    if req.id:
        print("mark exists")
        m: Mark = Mark.objects.filter(id=req.id)[0]
        if req.value != '':
            m.val = req.value
            m.save()
        else:
            m.delete()
    else:
        print("new mark")
        m = Mark(
            student_id=req.student_id,
            val=req.value,
            lesson=lesson,
        )
        m.save()

    data = {
        "id": m.id,
    }
    print(m)
    return HttpResponse(json.dumps(data))
