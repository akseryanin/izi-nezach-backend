from django.http import HttpResponseRedirect, HttpResponse

def journal_index_redirect(request):
    return HttpResponseRedirect('journal')
