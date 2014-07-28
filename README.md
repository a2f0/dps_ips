Overview
========

dps_ips is a basic IPS written in perl.  It integrates and implements several open source technologies including mysql, perl, syslog-ng, sec.pl, and cron. It detects 'unwanted' events using sec.pl and then dynamically provisions and maintains shuns in an ASA firewall.
Sec.pl keeps track of the last time the nefarious activity was detected, and cleans up shuns after a defined threshold.  

Installation
-------------

1. named pipe configuration:

        sudo mkdir /pipes  
        cd /pipes  
        sudo mkfifo sec  
        sudo chown dps:admin sec  

2. syslog-ng configuration:

    Make modifications in syslog-ng.conf (write to the pipe)

        source UDP4333 {
          udp(port(4333));
        };
        
        destination sec {
          pipe("/pipes/sec ");
        };

3. SEC Configuration

    Copy the asa.sec somewhere on the system.

4. MySQL Setup

    create the MySQL Database

        mysqladmin -u root -p create ds_ips

    import the databae

        mysql -u root -p --database dps_ips < user_load.sql

5. Schedule the cron job.

        */5 * * * * /Users/dps/documents/personal/ds_ips.pl -c

6. Download sec.pl (tested with 2.5.1) from here:

    http://sourceforge.net/projects/simple-evcorr/files/sec/2.5.1/

Execution
----------

    perl -w sec.pl -conf=asa.sec -intevents -input=/pipes/sec \
    -pid=/pid/asa.pid -blocksize=1024 -log=/var/log/asa.log \
    -debug=6

Troubleshooting
---------------

listening to the pipe to test:

    tail -f /pipes/sec

putting the test data into the pipe to make sure it works:

    cat /Users/dps/documents/Personal/CSPP/syslog_data > /pipes/sec
