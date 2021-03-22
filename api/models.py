from maintenance.helpers.named_tuple import namedtuple_wrapper

rMark = namedtuple_wrapper(
    "requestMark",
    [
        "value",
        "id",
        "student_id",
        "subject_id",
        "teacher_id",
        "lesson_id",
    ]
)

rLesson = namedtuple_wrapper(
    "requestLesson",
    [
        "name",
        "date",
        "subject_id",
        "squad_id",
    ]
)

