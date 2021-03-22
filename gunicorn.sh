#!/bin/bash

NAME="djour"                                    # Name of the application
DJANGODIR=/home/boris/Projects/djour/                           # Django project directory
SOCKFILE=/home/boris/Projects/djour/gunicorn.sock           # we will communicte using this unix socket
USER=boris                                         # the user to run as
GROUP=boris                                        # the group to run as
NUM_WORKERS=3                                     # how many worker processes should Gunicorn spawn
DJANGO_SETTINGS_MODULE=djour.settings           # which settings file should Django use
DJANGO_WSGI_MODULE=djour.wsgi                   # WSGI module name

echo "Starting $NAME as `whoami`"

# Create the run directory if it doesn't exist
RUNDIR=$(dirname $SOCKFILE)
test -d $RUNDIR || mkdir -p $RUNDIR

# Start your Django Unicorn
# Programs meant to be run under supervisor should not daemonize themselves (do not use --daemon)
gunicorn ${DJANGO_WSGI_MODULE}:application \
  --name $NAME \
  --workers $NUM_WORKERS \
  --user=$USER --group=$GROUP \
  --bind=unix:$SOCKFILE \
  --log-level=debug \
  --log-file=-
