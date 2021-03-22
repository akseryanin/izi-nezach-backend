from django.shortcuts import render
from journal.models import Attendance, UserExtension
from maintenance.helpers.named_tuple import namedtuple_wrapper
from journal import constants
from journal.managers.context import with_context, get_user_extension
from datetime import date

tAttendanceRestriction = namedtuple_wrapper(
    'tAttendanceRestriction',
    (
        'date_restricted',
        'date',
        'squads',
        'can_edit',
    )
)


def attendance(request):
    restrictions = None
    try:
        ext = UserExtension.objects.get(user=request.user)
    except UserExtension.DoesNotExist:
        ext = None
    if ext:
        allowed_squads = ext.squads.all()
        f = Attendance.objects.filter(squad__in=allowed_squads)
        restrictions = tAttendanceRestriction(
            date_restricted=ext.date_limit,
            date=date.today(),
            squads=allowed_squads,
            can_edit=ext.can_edit_attendance,
        )
    else:
        # all forms, no restrictions
        f = Attendance.objects.all()

    return render(
        request,
        "journal/attendance.html",
        with_context({
            "forms": f,
            "restrictions": restrictions
        })
    )


def edit_attendance(request, attendance_id):
    att: Attendance = Attendance.objects.filter(id=attendance_id)[0]
    context = {}
    ext = get_user_extension(request.user)
    if ext:
        if not ext.can_edit_attendance:
            context = {
                "error": "Этот пользователь не может изменять строевые записки"
            }
        elif ext.date_limit and att.date != date.today():
            context = {
                "error": "Этот пользователь не может изменять строевые записки за даты, отличающейся от текущей"
            }

    types = constants.ATT_TYPES
    if not context:
        context = {
            "students": att.students.all().order_by('student__last_name').prefetch_related('student'),
            "statuses": att.students.all().order_by('student__last_name').prefetch_related('student'),
            "attendance_types": types,
            "attendance_id": attendance_id,
            "squad_code": att.squad.code,
            "date": att.date,
        }

    return render(
                request,
                "journal/attendance_edit.html",
                with_context(context)
            )
