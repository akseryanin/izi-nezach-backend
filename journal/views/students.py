from datetime import date, timedelta
from django.shortcuts import render
from django.contrib.auth.decorators import login_required
from django.views.decorators.csrf import ensure_csrf_cookie

from journal.managers.context import with_context
from journal.models import *
from journal.managers.marks import tAvg
from journal.views.common import avg_mark_student, get_attendance_stats
from maintenance.helpers.named_tuple import namedtuple_wrapper

tOption = namedtuple_wrapper(
    'tOption',
    (
        'code',
        'label'
    )
)

tCount = namedtuple_wrapper(
    'tCount',
    (
        'label',
        'count'
    )
)

tExamMark = namedtuple_wrapper(
    'tExamMark',
    (
        'semester',
        'marks'
    )
)


@ensure_csrf_cookie
@login_required
def students(request):
    ls: [Student] = Student.objects.all()
    for student in ls:
        student_info = PersonalInfo.objects.filter(student=student)
        if student_info:
            student.deducted = student_info[0].end_date is not None
        else:
            student.deducted = False
    return render(
        request,
        "journal/students.html",
        with_context({
            # "user_id": user_id,
            "students": ls,
        })
    )


@ensure_csrf_cookie
@login_required
def student(request, student_id):
    st: Student = Student.objects.filter(id=student_id).first()
    all_subjects = Subject.objects.filter(timetable__squad__code=st.squad)
    avgs = []
    for subj in all_subjects:
        avgs.append(tAvg(
            short=subj.short,
            avg=avg_mark_student(subj, student_id, date.today() - timedelta(weeks=300), date.today()),
            # exams=
        ))
        # todo оценки с учётом пропусков
        # avgs.append(tAvg(
        #     short=subj.short + ' (с пропусками)',
        #     avg=get_avg_for_subject(subj, student_id, absent_zero=True)
        # ))

    atts = StudentAttendance.objects.filter(student=st)

    info = PersonalInfo.objects.filter(student=st).first()

    all_attendances = Attendance.objects.filter(squad=st.squad)

    penalties = Penalty.objects.filter(student=st)

    penalty_choices = {
        Penalty.REPRIMAND: 'Взысканий',
        Penalty.PROMOTION: 'Поощрений',
    }
    penalties_got_map = {penalty_choices[Penalty.PROMOTION]: 0, penalty_choices[Penalty.REPRIMAND]: 0}

    for penalty in penalties:
        penalties_got_map[penalty_choices[penalty.type]] += 1

    penalty_stats = []
    for key, value in penalties_got_map.items():
        penalty_stats.append(tCount(label=key, count=value))

    duties = Duty.objects.filter(student=st)

    events = Event.objects.filter(eventparticipant__student=st).order_by('-date')

    return render(
        request,
        "journal/student.html",
        with_context({
            "student": st,
            "avg_marks": avgs,
            "attendance_stats": get_attendance_stats(atts),
            "info": info,
            "penalties": penalties,
            "penalty_options": _get_options(Penalty.CHOICES),
            "penalty_stats": penalty_stats,
            "all_attendances": all_attendances,
            "duty_options": _get_options(Duty.CHOICES),
            "duty_stats": _get_avg_duty_marks(st),
            "duties": duties,
            "all_exams": _get_exam_marks(st),
            "stud_events": events,
            "available_events": Event.objects.exclude(id__in=events).order_by('-date'),
            "all_events": Event.objects.all().order_by('-date')
        })
    )


def _get_penalties():
    pass


def _get_options(model_choices):
    opts = []
    for code, label in model_choices:
        opts.append(tOption(code=code, label=label))
    return opts


def _get_exam_marks(st: Student) -> dict:
    exams = Exam.objects.filter(squad=st.squad)
    all_subjects = Subject.objects.filter(timetable__squad__code=st.squad)
    result = {}
    for s in all_subjects:
        result[s.short] = []
        needed_exams = exams.filter(subject=s)
        for e in needed_exams:
            lessons = Lesson.objects.filter(exam=e)
            marks = _extract_exam_marks(lessons, st)
            display = '/'.join(marks)
            exam_mark = tExamMark(semester=e.semester, marks=display)
            result[s.short].append(exam_mark)
    return result


def _get_group_exam_marks(students: [Student], squad: Squad) -> dict:
    exams = Exam.objects.filter(squad=squad)
    all_subjects = Subject.objects.filter(timetable__squad__code=squad)
    result = {}
    for s in all_subjects:
        result[s.short] = []
        needed_exams = exams.filter(subject=s)
        for e in needed_exams:
            marks = _extract_exam_marks_group(e, students)
            display = '/'.join(marks)
            exam_mark = tExamMark(semester=e.semester, marks=display)
            result[s.short].append(exam_mark)
    return result


def _extract_exam_marks(ls: [Lesson], st: Student):
    marks = []
    for l in ls:
        mark = Mark.objects.filter(lesson=l, student=st).first()
        if mark:
            marks.append(str(mark.val))
    return marks


def _extract_exam_marks_group(ls: [Lesson], st: [Student]):
    marks = []
    for l in ls:
        mark = Mark.objects.filter(lesson=l, student_id__in=st).order_by()
        if mark:
            marks.append(str(mark.val))
    return marks


def _get_avg_duty_marks(st_obj):
    duties_choices = {
        Duty.DETENTION: 'Наряд по кафедре',
        Duty.DUTY: 'Дежурство по взводу',
    }
    avgs = {duties_choices[Duty.DETENTION]: 0, duties_choices[Duty.DUTY]: 0}

    duties = Duty.objects.filter(student=st_obj)

    for type, label in duties_choices.items():
        duties_by_type = duties.filter(type=type)
        if not duties_by_type:
            avgs[label] = '-'
        else:
            for duty in duties_by_type:
                avgs[label] += duty.mark
            avgs[label] /= duties_by_type.count()

    output = []
    for duty, mark in avgs.items():
        output.append(tCount(label=duty, count=mark))

    return output
