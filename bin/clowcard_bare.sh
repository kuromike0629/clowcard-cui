#!/bin/bash
bundle exec clowcard_cui tomoyo_learning_bare $1
chmod 777 $1
$1
bundle exec clowcard_cui tomoyo_stop_learning_bare $1 $2
