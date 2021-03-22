import datetime as dt
from django.http import HttpResponseRedirect
from api.forms import NewEventForm, SetEventForm
from journal.models import Student, Event, EventParticipant


def add_event(request):
    if request.method == 'POST':
        form = NewEventForm(request.POST)
        name = form.data['name']
        date = form.data['date']

        event = Event(
            name=name,
            date=dt.datetime.strptime(date, '%d-%m-%Y')
        )
        event.save()

    return HttpResponseRedirect(request.META.get('HTTP_REFERER', '/'))


def set_event(request):
    if request.method == 'POST':
        form = SetEventForm(request.POST)
        student_id = form.data['student_id']
        event_id = form.data['event_id']

        event_connections = EventParticipant(
            student_id=student_id,
            event_id=event_id
        )
        event_connections.save()

    return HttpResponseRedirect(request.META.get('HTTP_REFERER', '/'))
