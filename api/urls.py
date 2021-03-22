from django.urls import path

import api.views as views


urlpatterns = [
    path('marks/add', views.add_mark, name='marks_add'),
    path('lessons/add', views.add_lesson, name='lessons_add'),
    path('attendance/add', views.add_attendance, name='attendance_add'),
    path('attendance/set', views.set_attendance, name='attendance_set'),
    path('penalty/add', views.add_penalty, name='penalty_add'),
    path('duty/add', views.add_duty, name='duty_add'),
    path('event/add', views.add_event, name='event_add'),
    path('event/set', views.set_event, name='event_set'),
    # path("<int:user_id>", views.borrower_page, name="borrower_page")
]
