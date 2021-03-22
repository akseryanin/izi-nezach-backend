from django.shortcuts import render
from datetime import date, timedelta, datetime
from django.db.models import QuerySet
from django.contrib.auth.decorators import login_required

from journal.managers.context import with_context
from journal.models import *
from maintenance.helpers.named_tuple import namedtuple_wrapper
from journal.views.common import avg_mark_student, avg_marks_group, get_attendance_stats, students_to_ids, \
    _count_mark_group, for_subj_mark_student, for_subj_marks_group

tStudentRow = namedtuple_wrapper(
    'tStudentRow',
    (
        'student',
        'avg_marks',
        'attendance',
        'total_reprimands',
        'total_promotions'
    )
)

tUnitRow = namedtuple_wrapper(
    'tUnitRow',
    (
        'unit',
        'rows',
        'subtotal',
    )
)

tSubjectMark = namedtuple_wrapper(
    'tSubjectMark',
    (
        'semester',
        'mark',
    )
)

tSubjectAvgs = namedtuple_wrapper(
    'tSubjectAvgs',
    (
        'subject',
        'avgs',
    )
)

tUnitAvgs = namedtuple_wrapper(
    'tUnitAvgs',
    (
        'num',
        'val',
    )
)


@login_required()
def squad_stats(request, squad_code='1701'):
    try:
        if 'to' in request.GET:
            to_date = datetime.strptime(request.GET.get('to'), '%d-%m-%Y')
        else:
            to_date = date.today()
        if 'from' in request.GET:
            from_date = datetime.strptime(request.GET.get('from'), '%d-%m-%Y')
        else:
            from_date = to_date - timedelta(days=30)
    except:
        context = {
            "error": "Неправильный формат даты",
            'squad_code': squad_code
        }
        return render(
            request,
            "journal/squad_stats.html",
            with_context(context)
        )
    squad = Squad.objects.get(code=squad_code)
    students = Student.objects.filter(squad=squad).order_by('unit', 'last_name')
    subjects = Subject.objects.filter(timetable__squad__code=squad_code)

    return render(
        request,
        "journal/squad_stats.html",
        with_context({
            'subjects': subjects,
            'unit_rows': _make_unit_rows(students, subjects, from_date, to_date),
            'total': _make_squad_total(students, subjects, from_date, to_date),
            'units': _get_units_marks(students, subjects, from_date, to_date),
            'from_date': from_date,
            'to_date': to_date,
            'squad_code': squad_code
        })
    )


def _get_units_marks(students, subjects, from_date: date, to_date: date):
    result = []
    for i in range(1, 4):
        unit_students = students.filter(unit=i).all()
        result.append(tUnitAvgs(num=i, val=_get_unit_marks(subjects, unit_students, from_date, to_date)))
    return result


def _extract_exam_marks(ls: Lesson, st: Student):
    mark = Mark.objects.filter(lesson=ls, student=st).filter(val__in=[1, 2, 3, 4, 5]).first()
    print(mark)
    if mark is None:
        return 0
    return mark.val


def _lessons_to_ids(lessons: [Lesson]):
    return [l.id for l in lessons]


def _get_unit_marks(subjects, students, from_date: date, to_date: date):
    result = []
    for subj in subjects:
        all_marks = {}
        for st in students:
            exams = Exam.objects.filter(squad=st.squad)
            needed_exams = exams.filter(subject=subj)
            for e in needed_exams:
                # lesson = Lesson.objects.filter(exam=e).order_by('-attendance__date').first()
                lessons = Lesson.objects.filter(exam=e)
                mark = Mark.objects.filter(lesson_id__in=_lessons_to_ids(lessons), val__gt=0, student=st).order_by(
                    '-lesson__attendance__date').first()
                # ffmark = _extract_exam_marks(lesson, st)
                if mark is not None:
                    if e.semester in all_marks:
                        all_marks[e.semester].append(mark)
                    else:
                        all_marks[e.semester] = [mark]
        avgs = [
            tSubjectMark(semester=subj_name, mark=round(sum([mark.val for mark in marks]) / len(marks), 2))
            for subj_name, marks in all_marks.items()
        ]
        for_subj = [
            tSubjectMark(semester=subj_name, mark=_count_mark_group(marks))
            for subj_name, marks in all_marks.items()
        ]
        # result.append(tSubjectAvgs(subject=subj.short + ' (ср.)', avgs=avgs))
        result.append(tSubjectAvgs(subject=subj.short, avgs=for_subj))
    return result


def _make_squad_total(students, subjects, from_date: date, to_date: date):
    avg_marks = []
    for subj in subjects:
        avg_marks.append(for_subj_marks_group(students, subj, from_date, to_date))
        avg_marks.append(avg_marks_group(students, subj, from_date, to_date))
    return tStudentRow(
        avg_marks=avg_marks,
        attendance=get_attendance_stats(StudentAttendance.objects.filter(student_id__in=students_to_ids(students),
                                                                         attendance__date__gte=from_date,
                                                                         attendance__date__lte=to_date)),
        total_reprimands=len(Penalty.objects.filter(student_id__in=students_to_ids(students), type='reprimand',
                                                    attendance__date__gte=from_date,
                                                    attendance__date__lte=to_date)),
        total_promotions=len(Penalty.objects.filter(student_id__in=students_to_ids(students), type='promotion',
                                                    attendance__date__gte=from_date,
                                                    attendance__date__lte=to_date)),
    )


def _make_unit_rows(students: QuerySet, subjects, from_date: date, to_date: date):
    ls = []
    for (u, _) in Student.UNIT_CHOICES:
        unit_students = students.filter(unit=u).order_by('journal_id')
        rows = _make_rows(unit_students, subjects, from_date, to_date)
        # total = _make_subtotal(unit_students, subjects)
        ls.append(tUnitRow(
            rows=rows,
            unit=u,
            subtotal=_make_subtotal(unit_students, subjects, from_date, to_date),
        ))
    return ls


def _make_subtotal(students, subjects, from_date: date, to_date: date):
    avg_marks = []
    for subj in subjects:
        avg_marks.append(for_subj_marks_group(students, subj, from_date, to_date))
        avg_marks.append(avg_marks_group(students, subj, from_date, to_date))
    return tStudentRow(
        # student=student,
        avg_marks=avg_marks,
        attendance=get_attendance_stats(StudentAttendance.objects.filter(student_id__in=students_to_ids(students),
                                                                         attendance__date__gte=from_date,
                                                                         attendance__date__lte=to_date)),
        total_reprimands=len(Penalty.objects.filter(student_id__in=students_to_ids(students), type='reprimand',
                                                    attendance__date__gte=from_date,
                                                    attendance__date__lte=to_date)),
        total_promotions=len(Penalty.objects.filter(student_id__in=students_to_ids(students), type='promotion',
                                                    attendance__date__gte=from_date,
                                                    attendance__date__lte=to_date)),
    )


def _make_rows(students, subjects, from_date: date, to_date: date):
    return [_make_row(student, subjects, from_date, to_date) for student in students]


def _make_row(student: Student, subjects: [Subject], from_date: date, to_date: date) -> tStudentRow:
    avg_marks = []
    for subj in subjects:
        avg_marks.append(for_subj_mark_student(subj, student.id, from_date, to_date))
        avg_marks.append(avg_mark_student(subj, student.id, from_date, to_date))
    return tStudentRow(
        student=student,
        avg_marks=avg_marks,
        attendance=get_attendance_stats(
            StudentAttendance.objects.filter(student=student, attendance__date__gte=from_date,
                                             attendance__date__lte=to_date)),
        total_reprimands=len(Penalty.objects.filter(student=student, type='reprimand', attendance__date__gte=from_date,
                                                    attendance__date__lte=to_date)),
        total_promotions=len(Penalty.objects.filter(student=student, type='promotion', attendance__date__gte=from_date,
                                                    attendance__date__lte=to_date)),
    )
