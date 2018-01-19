# ClowCardCUI

ClowCard is "Container type Linux prOgram and malWare Cretical Analysing tools powerd by tomoyolinux,Ruby and Docker".

## Installation

1.Install Libraries(Working on Ubuntu:16.04)

Install TomoyoTools:

    $sudo apt install tomoyo-tools
    
    $sudo tomoyo-init

Install Docker:

See Official page of Docker(https://www.docker.com)

Ruby Libraries Execute:

    $ bundle install
    
## Usage

How to Use ClowcardCUI:

1.Analysis

    $sudo bundle exec bin/clowcard_cui analysis [optical tag] [malware_path] [execute_time(second)] [output_policy_path]

## Contributing

Bug reports and pull requests are welcome on GitHub at https://github.com/kuromike0629/clowcard_cui.
