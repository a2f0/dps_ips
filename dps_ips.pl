#!/usr/bin/perl 

use lib "/opt/local/lib/perl5/vendor_perl/5.8.8/darwin-2level/";
use strict;
use warnings;
use DBI;
use DBD::mysql;
use Expect;
use Getopt::Std;
use DateTime;

my %opts;
getopts('hdc', \%opts);
my $sourceip = $ARGV[0];
my $destinationip = $ARGV[1];
my $destinationport = $ARGV[2];
my $protocol = $ARGV[3];
$protocol = lc($protocol);
my @timedata = localtime(time);
my $second = $timedata[0];
my $minute = $timedata[1];
my $hour = $timedata[2];
my $day = $timedata[3];
my $month = $timedata[4];
my $year = $timedata[5] + 1900;
my $database = "ds_ips";
my $havent_heard_from_nasty_host_window = "15";
my $ciscocommand = "";

my $dt = DateTime->new( year => $year,
    month => $month,
    day => $day,
    hour => $hour,
    minute => $minute,
    second => $second,
);

my $duration = DateTime::Duration->new ( minutes=> $havent_heard_from_nasty_host_window);
my $earliest_last_occurrence_max = $dt->add_duration($duration);
my $dbhost = "localhost";
my $dbport = "3306";
my $dbuser = "root";
my $dbpass = "";
my $mysql_friendly_time = "$year-$month-$day $hour:$minute:$second"; 
my $dsn = "DBI:mysql:database=$database;host=$dbhost;port=$dbport;mysql_socket=/tmp/mysql.sock";
my $dbh = DBI->connect($dsn, $dbuser, $dbpass);

if ( $opts{ 'h' }) { &processhammer() };
if ( $opts{ 'd' }) { &processdeny() }; 
if ( $opts{ 'c' }) { &processcleanup() };

sub processhammer 
{
    $dbh->do("INSERT INTO ds_ips (lastoccurred, sourceip, destinationip, destinationport, protocol) VALUES ('$mysql_friendly_time', '$sourceip', '$destinationip', '$destinationport','$protocol')");           
    $ciscocommand="access-list outside-in extended deny $protocol host $sourceip host $destinationip eq $destinationport"; 
    &executeasacmd($ciscocommand);
}

sub processdeny
{
    my $sth=$dbh->do("SELECT COUNT(*) FROM ds_ips WHERE sourceip = '$sourceip' AND destinationip = '$destinationip' AND destinationport = '$destinationport' AND protocol = '$protocol'");
    if ($sth>=1)
    {
        $dbh->do("UPDATE ds_ips SET lastoccurred = '$mysql_friendly_time' WHERE sourceip = '$sourceip' AND destinationip = '$destinationip' AND destinationport = '$destinationport' AND protocol = '$protocol'");
    }
}

sub processcleanup
{
    my $sth=$dbh->prepare("SELECT * FROM ds_ips WHERE lastoccurred < '$earliest_last_occurrence_max'"); 
    $sth->execute();

    while (my $ref = $sth->fetchrow_hashref()) {
        $sourceip = $ref -> {'sourceip'};
        $destinationip = $ref -> {'destinationip'};
        $destinationport = $ref -> {'destinationport'};
        $protocol = $ref -> {'protocol'}; 
        $ciscocommand="no access-list outside-in extended deny $protocol host $sourceip host $destinationip eq $destinationport";   
        &executeasacmd($ciscocommand);
    }
    
    $sth->finish();
}

sub executeasacmd
{
    $ciscocommand=shift; 
    #acess-listed
    my $host="10.135.2.30";
    my $ssh_path="/usr/bin/ssh";
    my $username="firewalladmin";
    my $password="p\@ssw0rd";
    my $expect_timeout="5";
    my $password_prompt="password:";
    my $enable_prompt="Password:";
    my $enabled_prompt="#";
    my $configure_prompt="#";
    my $configure_command="configure terminal";
    my $cisco_command_turn_pager_lines_off="pager 0";
    my $process_to_spawn="$ssh_path $username\@$host";  
    my $expect_object = new Expect();
    $expect_object->raw_pty(1);
    $expect_object->spawn("$process_to_spawn") or die ("Unable to spawn: \"$process_to_spawn\".  Please check the syntax of this command.");
    $expect_object->slave->stty(qw(raw -echo));
    $expect_object->stty(qw(raw -echo));
    $expect_object->expect($expect_timeout, -re => "$password_prompt") or die ("Did not get user password prompt: \"$password_prompt\"");
    print $expect_object "$password\r";
    print $expect_object "enable\n";
    $expect_object->expect($expect_timeout, -re => "$enable_prompt") or die ("Did not get enable password prompt: \"$enable_prompt\"");
    print $expect_object "$password\r";
    $expect_object->expect($expect_timeout, -re => "$enabled_prompt") or die ("Did not get enabled prompt: \"$enabled_prompt\"");
    print $expect_object "$configure_command\r";
    $expect_object->expect($expect_timeout, -re => "$configure_prompt") or die ("Did not get configure prompt: \"$configure_prompt\""); 
    print $expect_object "$ciscocommand\r"; 
    print $expect_object "write memory\r";
    print $expect_object "disable\r";
    print $expect_object "exit\r";
    $expect_object->soft_close();
}
