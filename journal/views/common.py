from datetime import date
from collections import Counter
from journal.models import Mark, StudentAttendance


def avg_mark_student(subject, student_id, from_date, to_date, absent_zero=False):
    if absent_zero:
        marks = Mark.objects.filter(student_id=student_id, lesson__subject=subject,
                                    lesson__attendance__date__gte=from_date, lesson__attendance__date__lte=to_date)
    else:
        marks = Mark.objects.filter(student_id=student_id, lesson__subject=subject, val__gt=0,
                                    lesson__attendance__date__gte=from_date, lesson__attendance__date__lte=to_date)
    return _avg_mark(marks)


def avg_marks_group(students, subj, from_date: date, to_date: date):
    return _avg_mark(
        Mark.objects.filter(lesson__subject=subj, student_id__in=students_to_ids(students), val__gt=0,
                            lesson__attendance__date__gte=from_date, lesson__attendance__date__lte=to_date)
    )


def for_subj_marks_group(students, subj, from_date: date, to_date: date):
    return _count_mark_group(
        Mark.objects.filter(lesson__subject=subj, student_id__in=students_to_ids(students), val__gt=0,
                            lesson__attendance__date__gte=from_date, lesson__attendance__date__lte=to_date)
    )


def for_subj_mark_student(subject, student_id, from_date, to_date, absent_zero=False):
    if absent_zero:
        marks = Mark.objects.filter(student_id=student_id, lesson__subject=subject,
                                    lesson__attendance__date__gte=from_date, lesson__attendance__date__lte=to_date)
    else:
        marks = Mark.objects.filter(student_id=student_id, lesson__subject=subject, val__gt=0,
                                    lesson__attendance__date__gte=from_date, lesson__attendance__date__lte=to_date)
    return _count_mark_student(marks)


def students_to_ids(students):
    return [s.id for s in students]


def _avg_mark(marks: [Mark]):
    avg, cnt = 0, 0
    # todo разобраться с Avg и Case/When
    for m in marks:
        m: Mark = m
        if m.val < 0:
            m.val = 0
        avg += m.val
        cnt += 1
    if cnt > 0:
        avg /= cnt
    else:
        avg = None
    return avg


def _count_mark_student(marks: [Mark]):
    counter = Counter([mark.val for mark in marks])
    histogram = counter.copy()
    total = sum(histogram.values())
    if total == 0:
        return None
    for mark in histogram:
        histogram[mark] /= total
    if histogram[5] >= 0.5 and (histogram[4] + histogram[5] == 1):
        return 5
    elif (histogram[4] + histogram[5] >= 0.5) and (histogram[3] + histogram[4] + histogram[5] == 1):
        return 4
    elif counter[2] <= 1:
        return 3
    else:
        return 2


def _count_mark_group(marks: [Mark]):
    counter = Counter([mark.val for mark in marks])
    histogram = counter.copy()
    total = sum(histogram.values())
    if total == 0:
        return None
    for mark in histogram:
        histogram[mark] /= total
    if histogram[5] >= 0.45 and (histogram[3] + histogram[4] + histogram[5] >= 0.9):
        return 5
    elif (histogram[4] + histogram[5] >= 0.4) and (histogram[3] + histogram[4] + histogram[5] >= 0.8):
        return 4
    elif histogram[3] + histogram[4] + histogram[5] >= 0.7:
        return 3
    else:
        return 2


def get_attendance_stats(atts: [StudentAttendance]) -> dict:
    stats = {
        "absent": 0,
        "truant": 0,
        "duty": 0,
        "present": 0,
    }
    for a in atts:
        a: StudentAttendance = a
        stats[a.value] += 1
    stats["total"] = stats["truant"] + stats["absent"] + stats["duty"]
    return stats
