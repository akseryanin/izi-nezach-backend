from django.shortcuts import render
from journal.models import Event, EventParticipant
from journal.managers.context import with_context
from maintenance.helpers.named_tuple import namedtuple_wrapper

tEventsParts = namedtuple_wrapper(
    'tEventsParts',
    (
        'event',
        'participants'
    )
)


def events(request):
    f = Event.objects.all().order_by('-date')
    f = get_participants(f)

    return render(
        request,
        'journal/events.html',
        {'forms': f, }
    )


def get_participants(events):
    response = []
    for event in events:
        ps = EventParticipant.objects.filter(event=event).all().order_by('student__squad__code', 'student__last_name')
        response.append(tEventsParts(event=event, participants=ps))
    return response