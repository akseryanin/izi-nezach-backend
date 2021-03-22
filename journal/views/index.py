from django.shortcuts import render

from journal.managers.context import with_context


from django.contrib.auth.decorators import login_required

@login_required()
def index(request):
    name = "boris"
    if request.GET.get('mybtn'):
        name = str(request.GET.get('mytextbox'))

    return render(
        request,
        "journal/index.html",
        with_context({
            "user": name
        })
    )
