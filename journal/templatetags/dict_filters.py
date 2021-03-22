from django import template

register = template.Library()


@register.filter(name='get_dict_value')
def get_dict_value(dict, key):
    return dict.get(key)


@register.filter()
def get_exact_sem(ts, i):
    for t in ts:
        if str(t.semester) == str(i):
            return t