from journal.models import Squad, Subject, UserExtension
from django.shortcuts import render
from maintenance.helpers.named_tuple import namedtuple_wrapper

tSquadSubject = namedtuple_wrapper(
    "tSquadSubject",
    [
        "id",
        "code",
        "subjects",
    ]
)

ERROR_403 = (
    """<h3 class="header-wo-margin" align="center">Недостаточно прав!</h3>"""
    """<p class="text-muted header-comment" align="center">"""
    "{}"
    "</p>"
)


def get_squads_with_subjects():
    ans = []
    for s in Squad.objects.order_by('code'):
        q = Subject.objects.filter(timetable__squad__code=s.code).prefetch_related(
            'timetable_set__squad'
        )
        ans.append(tSquadSubject(
            code=s.code,
            id=s.id,
            subjects=q,
        ))
    return ans



tMarkValues = namedtuple_wrapper(
    "tMarkValues",
    [
        "id",
        "code",
        "subjects",
    ]
)



def with_context(d: dict):
    squads = get_squads_with_subjects()
    d["squad_list"] = squads
    return d



def get_user_extension(user):
    try:
        ext = UserExtension.objects.get(user=user)
    except UserExtension.DoesNotExist:
        ext = None
    return ext

