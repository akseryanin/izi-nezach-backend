# This is an auto-generated Django model module.
# You'll have to do the following manually to clean this up:
#   * Rearrange models' order
#   * Make sure each model has one field with primary_key=True
#   * Make sure each ForeignKey has `on_delete` set to the desired behavior.
#   * Remove `managed = True` lines if you wish to allow Django to create, modify, and delete the table
# Feel free to rename the models, but don't rename db_table values or field names.
from django.db import models
from django.core.exceptions import ValidationError
from django.contrib.auth.models import User
from image_cropping import ImageRatioField



# from journal.managers.marks import student_short_name


class Attendance(models.Model):
    """ строевая записка"""
    date = models.DateField(blank=True, null=True, verbose_name='Дата')
    squad = models.ForeignKey('journal.Squad', models.CASCADE, blank=False, null=True, verbose_name='Взвод')
    students = models.ManyToManyField('journal.StudentAttendance', verbose_name='Студенты')


    @property
    def absent(self):
        return len(self.students.filter(value__iregex='(absent|truant)'))


    @property
    def datestr(self):
        return self.date.strftime("%Y%m%d%H%M%s")


    def __str__(self):
        return f'Строевая записка {self.squad.code} от {self.date.strftime("%Y-%m-%d")}'


    class Meta:
        managed = True
        db_table = 'attendance'
        verbose_name = 'Строевая записка'
        verbose_name_plural = 'Строевая записка'
        constraints = [
            models.UniqueConstraint(fields=('date', 'squad'), name='date/squad pair')
        ]



class StudentAttendance(models.Model):
    student = models.ForeignKey('journal.Student', models.CASCADE)
    value = models.CharField(max_length=20, blank=True, null=True)


    class Meta:
        managed = True



class StudentAttendanceType(models.Model):
    value = models.CharField(max_length=100, blank=True, null=True)
    name = models.CharField(max_length=100, blank=True, null=True)


    class Meta:
        managed = True
        db_table = 'attendance_types'



class Duty(models.Model):
    DUTY = 'duty'
    DETENTION = 'detention'
    CHOICES = (
        (DUTY, 'дежурство'),
        (DETENTION, 'наряд'),
    )

    student = models.ForeignKey('journal.Student', models.CASCADE)
    type = models.CharField(
        'Вид',
        max_length=20,
        choices=CHOICES,
        default=DUTY,
    )
    attendance = models.ForeignKey(Attendance, models.CASCADE, blank=True, null=True, verbose_name="Дата")
    mark = models.IntegerField(blank=True, null=True)
    comment = models.CharField(max_length=100, blank=True, null=True)


    @property
    def russian_type(self):
        if self.type == self.DETENTION:
            return self.CHOICES[1][1]
        return self.CHOICES[0][1]


    class Meta:
        managed = True
        db_table = 'duties'



#
# class DutyType(models.Model):
#     name = models.CharField(unique=True, max_length=100)
#
#     class Meta:
#         managed = True
#         db_table = 'duty_types'


class EventParticipant(models.Model):
    student = models.ForeignKey('journal.Student', models.CASCADE, verbose_name='Студент')
    event = models.ForeignKey('journal.Event', models.CASCADE, blank=True, null=True, verbose_name='Мероприятие')


    class Meta:
        managed = True
        db_table = 'event_participants'
        verbose_name = 'Участник мероприятия'
        verbose_name_plural = 'Участники мероприятия'



class Event(models.Model):
    name = models.CharField(max_length=100, verbose_name='Название')
    date = models.DateField(verbose_name='Дата')


    class Meta:
        managed = True
        db_table = 'events'
        verbose_name = 'Мероприятие'
        verbose_name_plural = 'Мероприятия'



class Exam(models.Model):
    SEMESTER_CHOICES = (
        (3, 3),
        (4, 4),
        (5, 5),
        (6, 6),
        (7, 7),
        (8, 8)
    )
    NAME_EXAM = 'exam'
    NAME_TEST = 'test'
    NAME_CHOICES = (
        (NAME_EXAM, 'Экзамен'),
        (NAME_TEST, 'Зачёт'),
    )
    """ Экзамен """
    subject = models.ForeignKey('journal.Subject', models.CASCADE, db_column='subject', verbose_name='Предмет')
    semester = models.IntegerField('Семестр', choices=SEMESTER_CHOICES, default=0)
    squad = models.ForeignKey('journal.Squad', models.CASCADE, verbose_name='Взвод', null=True)
    name = models.CharField('Форма контроля', max_length=100, choices=NAME_CHOICES, default="")


    @property
    def russian_name(self):
        if self.name == self.NAME_EXAM:
            return self.NAME_CHOICES[0][1]
        elif self.name == self.NAME_TEST:
            return self.NAME_CHOICES[1][1]
        return f'<{self.name}>'


    def __str__(self):
        return f'({self.squad.code}) {self.russian_name} по {self.subject.short} в {self.semester} семестре'


    def display(self):
        return f'{self.russian_name} по {self.subject.short}, {self.semester} семестр'


    class Meta:
        managed = True
        db_table = 'exams'
        verbose_name = 'Форма контроля'
        verbose_name_plural = 'Формы контроля'
        constraints = [
            models.UniqueConstraint(fields=('semester', 'subject', 'squad'), name='max_one_per_semester')
        ]



class Mark(models.Model):
    student = models.ForeignKey('journal.Student', models.CASCADE, blank=True, null=True)
    # teacher = models.ForeignKey('journal.Teacher', models.CASCADE, blank=True, null=True)
    # subject = models.ForeignKey('journal.Subject', models.CASCADE, blank=True, null=True)
    val = models.IntegerField(blank=True, null=True, verbose_name='Оценка')
    lesson = models.ForeignKey('journal.Lesson', models.CASCADE, blank=True, null=True, verbose_name='Предмет')


    class Meta:
        managed = True
        db_table = 'marks'


    def __str__(self):
        return f'{self.val} по {self.lesson.subject.short} ({self.student.short})'


    @property
    def to_display(self):
        return


    @property
    def from_display(self):
        pass



class Penalty(models.Model):
    REPRIMAND = 'reprimand'
    PROMOTION = 'promotion'
    CHOICES = (
        (REPRIMAND, 'взыскание'),
        (PROMOTION, 'поощрение'),
    )
    type = models.CharField(
        'Вид',
        max_length=20,
        choices=CHOICES,
        default=REPRIMAND,
    )
    comment = models.CharField(max_length=256, blank=True, null=True, verbose_name='Комментарий')
    student = models.ForeignKey('journal.Student', models.CASCADE, verbose_name='Студент')
    attendance = models.ForeignKey(Attendance, models.CASCADE, blank=True, null=True, verbose_name='Строевая записка')


    @property
    def russian_type(self):
        if self.type == self.PROMOTION:
            return self.CHOICES[1][1]
        return self.CHOICES[0][1]


    def __str__(self):
        return f'{self.student.short} {self.russian_type} от {self.attendance.date.strftime("%Y-%m-%d")}'


    class Meta:
        managed = True
        db_table = 'penalties'
        verbose_name = 'Дисциплинарная практика'
        verbose_name_plural = 'Дисциплинарные практики'



class Squad(models.Model):
    code = models.CharField(unique=True, max_length=4, blank=True, null=True, verbose_name='Номер')


    class Meta:
        managed = True
        db_table = 'squads'
        verbose_name = 'Взвод'
        verbose_name_plural = 'Взвода'


    def __str__(self):
        return f'{self.code}'



class Student(models.Model):
    UNIT_CHOICES = ((1, 1), (2, 2), (3, 3))
    last_name = models.CharField('Фамилия', max_length=50, blank=True, null=True)
    first_name = models.CharField('Имя', max_length=50, blank=True, null=True)
    middle_name = models.CharField('Отчество', max_length=50, blank=True, null=True)
    squad = models.ForeignKey(Squad, models.CASCADE, blank=True, null=True, verbose_name='Взвод')
    unit = models.IntegerField('Отделение', choices=UNIT_CHOICES, blank=True, null=True)
    journal_id = models.IntegerField('Номер в журнале', blank=True, null=True)
    pic = models.ImageField(upload_to='students_pic/', blank=True, null=True, verbose_name='Изображение')

    cropping = ImageRatioField('pic', '200x300')


    def __str__(self):
        return f'({self.squad.code}) {self.last_name} {self.first_name} {self.middle_name} [{self.id}]'


    @property
    def short(self) -> str:
        def __get0(s: str) -> str:
            if len(s) > 0:
                return s[0]
            return '?'


        return f'{self.last_name} {__get0(self.first_name)}. {__get0(self.middle_name)}.'


    class Meta:
        managed = True
        db_table = 'students'
        verbose_name = 'Студент'
        verbose_name_plural = 'Студенты'



class Subject(models.Model):
    short = models.CharField('Сокращённое название', max_length=10, blank=True, null=True)
    name = models.CharField('Полное название', max_length=255, blank=True, null=True)


    def __str__(self):
        return f'({self.short}) [{self.id}]'


    class Meta:
        managed = True
        db_table = 'subjects'
        verbose_name = 'Дисциплина'
        verbose_name_plural = 'Дисциплины'



class Teacher(models.Model):
    last_name = models.CharField('Фамилия', max_length=50, blank=True, null=True)
    first_name = models.CharField('Имя', max_length=50, blank=True, null=True)
    middle_name = models.CharField('Отчество', max_length=50, blank=True, null=True)
    rank = models.CharField('звание', max_length=50, blank=True, null=True)


    def __str__(self):
        return f'({self.last_name}) {self.first_name} {self.middle_name} {self.rank} [{self.id}]'


    class Meta:
        managed = True
        db_table = 'teachers'


class Lesson(models.Model):
    # squad = models.ForeignKey(Squad, models.CASCADE, blank=True, null=True)
    subject = models.ForeignKey(Subject, models.CASCADE, blank=True, null=True, verbose_name='Предмет')
    name = models.CharField('Название', max_length=100, blank=True, null=False)
    attendance = models.ForeignKey(Attendance, models.CASCADE, blank=True, null=True, verbose_name='Строевая записка')
    exam = models.ForeignKey('journal.Exam', models.CASCADE, blank=True, null=True, verbose_name="Экзамен")


    def clean(self):
        if self.subject != self.exam.subject:
            raise ValidationError('Дисциплины экзамена и занятия должны совпадать')


    def __str__(self):
        return f'({self.attendance.squad.code}) {self.subject.short} {self.attendance.date.strftime("%Y-%m-%d")} '


    class Meta:
        managed = True
        db_table = 'lessons'
        verbose_name = 'Занятие'
        verbose_name_plural = 'Занятия'



class PersonalInfo(models.Model):
    student = models.OneToOneField(Student, models.CASCADE, blank=False, null=False, verbose_name="Студент")

    passport_code = models.CharField('Серия паспорта', max_length=4, blank=True, null=False)
    passport_number = models.CharField('Номер паспорта', max_length=6, blank=True, null=False)
    passport_issued_date = models.DateField('Дата выдачи паспорта', blank=True, null=True)
    passport_issued = models.CharField('Кем выдан паспорт', max_length=512, blank=True, null=False)

    reg_address = models.CharField('Адрес регистрации', max_length=512, blank=True, null=False)
    fact_address = models.CharField('Адрес фактический', max_length=512, blank=True, null=False)

    phone = models.CharField('Номер телефона', max_length=30, blank=True, null=True)

    birth_place = models.TextField('Место рождения', blank=True, null=False)
    birth_date = models.DateField('Дата рождения', blank=True, null=True)

    family_status = models.CharField('Семейное положение', max_length=512, blank=True, null=False)
    family_members = models.CharField('Члены семьи', max_length=512, blank=True, null=False)

    start_date = models.DateField('Начало обучения', blank=True, null=True)
    end_date = models.DateField('Окончание обучения', blank=True, null=True)

    order_admission = models.CharField('№ приказа о зачислении', max_length=100, blank=True, null=True)
    order_deduction = models.CharField('№ приказа об отчислении', max_length=100, blank=True, null=True)

    commissariat = models.CharField('Военкомат', max_length=512, blank=True, null=False)
    medical_report = models.TextField('Врачебное заключение', blank=True, null=False)

    characteristic_first_year = models.TextField('Характеристика за 2 курс', blank=True, null=True)
    characteristic_second_year = models.TextField('Характеристика за 3 курс', blank=True, null=True)
    characteristic_third_year = models.TextField('Характеристика за 4 курс', blank=True, null=True)

    service_rank = models.CharField('Служба в ВС, звание', max_length=100, blank=True, null=False)

    conclusion = models.TextField('Категория годности', blank=True, null=True)

    faculty = models.CharField('Факультет', max_length=100, blank=True, null=True)
    program = models.CharField('Образовательная программа', max_length=100, blank=True, null=True)
    group = models.CharField('Группа', max_length=20, blank=True, null=True)


    def __str__(self):
        return f'({self.student.squad.code}) {self.student.last_name} {self.student.first_name} {self.student.middle_name} [{self.id}]'


    class Meta:
        managed = True
        db_table = 'student_info'
        verbose_name = 'Персональные данные'
        verbose_name_plural = 'Персональные данные'



class UserExtension(models.Model):
    user = models.OneToOneField(User, models.CASCADE, verbose_name="Имя пользователя")
    squads = models.ManyToManyField('journal.Squad', blank=True, verbose_name="Может редактировать взвода")

    date_limit = models.BooleanField(default=False, verbose_name="Ограничение на текущую дату")
    can_edit_attendance = models.BooleanField(default=False, verbose_name="Может изменять строевые записки")

    def __str__(self):
        return f'{self.user.username}'


    class Meta:
        managed = True
        verbose_name = 'Разрешения пользователя'
        verbose_name_plural = 'Разрешения пользователя'


class TimeTable(models.Model):
    squad = models.ForeignKey(Squad, models.CASCADE, blank=True, null=True, verbose_name='Взвод')
    subjects = models.ManyToManyField(Subject, blank=True, verbose_name='Предметы')

    def __str__(self):
        return f'Взвод {self.squad}'

    class Meta:
        managed = True
        db_table = 'timetable'
        verbose_name = 'Расписание'
        verbose_name_plural = 'Расписание'
