#!/bin/bash
bundle exec clowcard_cui create_malware_image malware $1
bundle exec clowcard_cui tomoyo_learning $1
docker run -it malware /bin/bash
bundle exec clowcard_cui tomoyo_stop_learning $1 $2
