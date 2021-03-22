from django.shortcuts import render
from journal.managers.context import with_context
from journal.managers.marks import students_to_keys, tKey, tMark, make_cells
from journal.models import Subject, Mark, Lesson, Student, Attendance, Squad, Exam, StudentAttendance

from django.contrib.auth.decorators import login_required
from django.views.decorators.csrf import ensure_csrf_cookie



@login_required
@ensure_csrf_cookie
def marks_squad(request, squad_code="1702", subject_id=1):
    subj = Subject.objects.filter(id=subject_id).first()
    y_keys = students_to_keys(Student.objects.filter(squad__code=squad_code))
    x_keys = lessons_to_keys(Lesson.objects.filter(attendance__squad__code=squad_code, subject_id=subject_id))

    squad = Squad.objects.filter(code=squad_code).first()
    all_marks = list(Mark.objects.filter(student__squad__code=squad_code, lesson__subject_id=subject_id, val__gt=0))
    all_marks.extend(get_fake_marks(squad, subj))
    marks = marks_to_keys(all_marks)
    header, cells = make_cells(x_keys, y_keys, marks)

    att = Attendance.objects.filter(squad=squad).order_by('-date')

    exams = Exam.objects.filter(subject_id=subject_id, squad=squad)
    print(exams)

    return render(
        request,
        "journal/marks/marks_squad.html",
        with_context({
            "squad_code": squad_code,
            "header": header,
            "cells": cells,
            "marks": marks,
            "subject": subj,
            "x_keys": x_keys,
            "y_keys": y_keys,
            "subject_id": subject_id,
            "attendance_list": att,
            "exam_list": exams,
        })
    )



def marks_to_keys(all_marks: [Mark]) -> [tMark]:
    return [
        tMark(
            id=m.id,
            x_key=m.lesson_id,
            y_key=m.student_id,
            val=m.val,
        ) for m in all_marks
    ]



def lessons_to_keys(lessons: [Lesson]) -> [tKey]:
    return [
        tKey(
            id=l.id,
            display=l.attendance.date.strftime("%d.%m"),
            sort=l.attendance.date,
            val=l.id,
            comment=l.name,
            exam_id=l.exam.id if l.exam is not None else None,
            exam_name=l.exam.russian_name if l.exam is not None else None
        ) for l in lessons
    ]



def get_fake_marks(squad, subject) -> [Mark]:
    marks = []
    lessons = Lesson.objects.filter(attendance__squad=squad, subject=subject)
    for lesson in lessons:
        for s in lesson.attendance.students.all():
            if s.value == "truant":
                val = -1
            elif s.value == "absent":
                val = -2
            elif s.value == "duty":
                val = -3
            else:
                continue
            marks.append(Mark(
                student=s.student,
                val=val,
                lesson=lesson,
            ))
    return marks
