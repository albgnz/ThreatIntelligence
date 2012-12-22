#!/usr/bin/perl -w

##############################################################################
#
# logforwarder - tails multiple logs based on globbing patterns read from a 
# file and forwards via tcp or udp (syslog)
#
# author: Albert Gonzalez, CTO 
# date: December 18th 2012
#
#
# Copyright SEMplicity Inc. 
#
##############################################################################

use lib "/opt/tail2syslog/";
use strict;
use Getopt::Std;
use File::stat;
use File::Glob ':glob';
use File::Tail;
use File::Basename;
use File::Path;
use File::Copy;
use File::stat;
use Fcntl qw(LOCK_EX LOCK_NB);
use Socket;
use Time::HiRes;
use Time::HiRes qw (sleep);
use Sys::Hostname;
use Cwd;

my $ver = "1.1";

my %options = (
	l => 0,
	s => 200,
	h => 0,
	D => 0,
	a => 0,
	n => 0,
	t => 0,
	u => 0,
	c => "paths.cfg",
	f => "user.info",
	p => 514,
	O => hostname,
	v => 0
);
getopts('hDantuvc:f:O:p:l:s:',\%options);


sub usage()
{
	print <<"DONE";

Usage: $0 -c config_file [options]

	-c	The -c parameter specifies the location of the configuration file for
		Tail2Syslog.

		Comment lines or blank lines are not allowed between
		parameters in the configuration file.

		Example config file:

		Destinations=1.1.1.1
		Globs=/root/logs/audit*
		ArchiveDir=/store/complete/
		DeletionThreshold=0

		For more complex configurations please look to the tail2syslog
		official documentation.

	-p	The -p parameter defines the port on the remote host where a
		syslog receiver is listening.

		If this parameter is not specified, by default Tail2Syslog uses TCP
		port 514 for sending events to QRadar.

	-D	The -D parameter defines that the script is to run in the
		foreground.
		
		If the -D parameter is not specified, then Tail2Syslog runs as a	
		background daemon and logs all internal messages to the local
		syslog service.

	-a	The -a parameter adds a properly formatted syslog header to the
		message.

		Tail2Syslog typically sends files as they appear in the unmodified
		state from the file you are tailing. Using the -a parameter formats
		the syslog header of the form <PRI>Mmm dd hh:mm:ss tag.

		If you do not use the -a parameter, the options -t, -f, and -O have
		no effect.

	-n	The -n parameter appends a new line to the end of the syslog
		message before sending.

	-t	The -t parameter overrides the default tag name in the optional
		syslog header (see -a).

		By default, the tag name is the executable name of the script.
		Using the -t parameter causes the tag name to be the filename
		from which the message was sent.

	-u	The -u parameter forces Tail2Syslog to send events using UDP.

		The default protocol is tcp for reliable delivery and because log
		messages may be truncated when using UDP.

	-s	The -s parameter sets the event per second (EPS) rate
		Tail2Syslog uses to forward events.

		The default rate is 200 EPS.

	-f	The -f parameter allows you to add a syslog facility to the header
		in the syslog message. (ie -f daemon.info)

		This parameter must be used in conjunction with the -a
		parameter.
	
		If a facility is not specified, then the default value is user.info.

	-O 	The -O parameter overrides the default hostname in the optional
		syslog headers.

		This parameter must be used in conjunction with the -a
		parameter.

	-l	The -l parameter allows you to define a logger for debug
		information.

		Your must specify a path and file if you use the -l parameter. For
		example, /bin/logger.

	-v	The -v parameter displays the version information for the Tail2Syslog. 
DONE
}

sub getTime()
{
	my $date = localtime;
	chomp($date);
	$date
}

# Make all of the exit conditions a bit cleaner
sub exitWithMessage($$)
{
	my $message = shift;
	my $status = shift;
	print STDOUT getTime().": $message\n";
	exit($status);
}

# list splitting function needed for input validation
sub splitList($)
{
        my $string = shift;
        my @list = ();

        foreach (split('\|', $string))
        {	
		$_ =~ s/^\s+//; #remove leading whitespace if there
		$_ =~ s/\s+$//; #remove trailing whitespace if there
		# fields should have no spaces within them
                if ( $_ =~ m/^\S+$/ )
                {
                        push(@list, $_);
                }
                else
                {
                        print STDERR getTime().": Error reading input, whitespace within '$_', whitespace is not allowed. Continuing, but will not use this value.\n";
                }

        }
        @list
}

# Make sure a tar function resides somewhere, this would 
# also be the place that an SE could change the zipping tool
# for archiving if necessary
my $tar;
my $taropts = "-czf";
my $tarSuffix = ".tar.gz"; 
if (-e "/bin/tar")
{
	$tar = "/bin/tar";
}
elsif (-e "/usr/bin/tar")
{
	$tar = "/usr/bin/tar";
}
else
{
	exitWithMessage("Cannot locate tar utility, which is required for archiving files.", -1);
}

# Configure logging if the option has been selected.
my $loggerOn = 0;
my $logger;
if ($options{l})
{
	if (! -e $options{l})
	{
        	exitWithMessage("Cannot locate logging utility '$options{l}', which is required for logging.", -1);
	}
	$logger = $options{l};
	$loggerOn = 1;
}

if (!defined($options{f}))
{
	exitWithMessage("Need to specify a syslog facility with -f option. For example '-f daemon.info', for further information, reference the tail2syslog help (./tail2syslog.pl -h)", -1);
}
# print the help
if($options{h})
{
        usage();
	exit(1);
}

#print the version
if($options{v})
{
	exitWithMessage("tail2syslog version - $ver", 1);
}

# Need to save the working directory for relative
# file paths to the config file, the daemonizing
# process will change the directory
my $workingDir =  &Cwd::cwd();
chomp($workingDir);
$workingDir = $workingDir . "/";

# cleanup/validate options
$options{O} =~ m/^(.*)$/;
my $syslogHost = $1;

# If we cannot open the supplied config file then
# we exit, without globs and IPs the script does nothing
if (!open (FH,$options{c})) 
{
	exitWithMessage("ERROR: Cannot open specified config_file [$options{c}], use option -h to see usage.", -1)
}

# Grab whatever was in the file for parsing.
my @cfgLines = <FH>;
close FH;

# configuration defaults
# note that these are global handles, mainly to avoid
# passing them through functions that don't need them 
# to get to functions that do
my @iplist;
my @globlist;
my $archive = "/store/complete/"; 
my $thresh = 0; #default is to not touch files at all, leave them unarchived wherever they are

# Obtain configuration values
foreach my $line (@cfgLines)
{
	if ($line =~ m/^Destinations=(.+)$/)
	{
		my $ips = $1;
		chomp($ips);	
		@iplist = splitList($ips);
	}
	elsif($line =~ m/^Globs=(.+)$/)
	{
		my $globs = $1;
		chomp($globs);
		@globlist = splitList($globs);
	}
	elsif($line =~ m/^ArchiveDir=(.+)$/)
	{
		$archive = $1;
		if (! -d $archive)
		{
			print STDOUT getTime().": Directory '$archive' does not exist, creating it.\n";
			eval { mkpath($archive) };
  			if ($@) 
			{
				exitWithMessage("Unable to create directory :$archive", -1);
  			}			  			
		}
	}
	elsif($line =~ m/^DeletionThreshold=(.+)$/)
	{
		if ( $1 =~ m/^(\d+)$/ )
		{
			$thresh = $1;
		}
		else
		{
			print STDOUT getTime().": Deletion Threshold non-numerical, defaulting to $thresh.\n"
		}
	}
}

# Need at least one dest IP
if (!@iplist)
{
	exitWithMessage("Need atleast one destination IP in the config file", -1);
}

# Also need atleast one glob
if (!@globlist)
{	
	exitWithMessage("Need atleast one globbing pattern in the config file.", -1);
}

# global socket handle
my @sockets;

# the following are used for process control
my $execName = basename($0);
my $lockFile = "/var/locklock";
my $pidFile = "/var/run";

# loop/exit condition
my $running = 1;
my $continue = 0;

my %socketHash = ();
my $currentSocket = 0;
my $currentMessage = 0;

# month-map for formatting syslog headers
my %monthMap = (
	"01" => "Jan",
	"02" => "Feb",
	"03" => "Mar",
	"04" => "Apr",
	"05" => "May",
	"06" => "Jun",
	"07" => "Jul",
	"08" => "Aug",
	"09" => "Sep",
	"10" => "Oct",
	"11" => "Nov",
	"12" => "Dec"
);

# syslog facility/severity map
my %syslog_facilities = (
	"kern" => 0,
	"user" => 8,
	"mail" => 16,
	"daemon" => 24,
	"auth" => 32,
	"syslog" => 40,
	"lpr" => 48,
	"news" => 56,
	"uucp" => 64,
	"cron" => 72,
	"authpriv" => 80,
	"ftp" => 88,
	"local0" => 128,
	"local1" => 136,
	"local2" => 144,
	"local3" => 152,
	"local4" => 160,
	"local5" => 168,
	"local6" => 176,
	"local7" => 184
);

my %syslog_severities = (
	"emerg" => 0,
	"alert" => 1,
	"crit" => 2,
	"err" => 3,
	"warning" => 4,
	"notice" => 5,
	"info" => 6,
	"debug" => 7
);

sub syslogPri($)
{
	(my $facSevString) = @_;
	my $facility = "user";
	my $severity = "info";
	if( $facSevString =~ m/^(kern|user|mail|daemon|auth|syslog|lpr|news|uucp|cron|authpriv|ftp|local[0-7])/ )
	{
		$facility = $1;
	}
	if( $facSevString =~ m/\.(emerg|alert|crit|err|warning|notice|info|debug)/ )
	{
		$severity = $1;
	}
	return $syslog_facilities{$facility} + $syslog_severities{$severity};
}

sub stubbornReconnect($$$)
{
	(my $host, my $port, my $sleepTime) = @_;
	my $added = 0;
	my $cont = 0;
	while(!$cont || !$continue)
	{
		my $socket = connectMe($host,$port);

		# We need to maintain a list of hosts and their corresponding socket connections,
		# this will allow us to cleanup correctly if we get interrupted for some reason,
		# eg. ECS restarting on our target box due to a deploy
		if ($socket)
		{
			my $duplicate = 0;
			for my $key (keys %socketHash)
			{
				if ($key eq $host)
				{
					$duplicate = 1;
				}
			}

			if (!$duplicate)
			{
				$socketHash{ $host } = $socket;
			}
		}

		# Logic to handle an array of multiple sockets, essntially
		# we add the socket when we try to connect, but it's possible that
		# we fail to connect, so when we retry we don't want to add the socket
		# again before deleting the failed socket we've already added
		if (!$added)
		{
			if ($loggerOn) { system("$logger [tail2syslog][".$options{c}."] adding socket connection to ".$host) };
			push(@sockets, $socket);
			$added = 1;
			$cont = 1;
		}
		else
		{
			if ($loggerOn) { system("$logger [tail2syslog][".$options{c}."] something wrong, not connected ") };
			pop(@sockets);
			push(@sockets, $socket);
			$cont = 1;
		}
		if( !$socket && $running )
		{
			sleep $sleepTime;
			next;
		}
		$continue = 1;
	}
}

sub connectMe($$)
{
	(my $host, my $port) = @_;
	local *SOCK;
	my $protoName = 'tcp';
	if( $options{u} )
	{
		$protoName = 'udp';
	}
	my $proto = getprotobyname($protoName);
	my $ipAddr = inet_aton($host);
	my $sockAddr = sockaddr_in($port,$ipAddr);
	if( $protoName eq 'tcp' )
	{
		unless( socket(SOCK,PF_INET,SOCK_STREAM,$proto) ) 
		{  
			print STDOUT getTime().": ERROR: unable to open socket: $!\n";
			return 0; 
		}
	}
	else
	{
		unless( socket(SOCK,PF_INET,SOCK_DGRAM,$proto) ) 
		{  
			print STDOUT getTime().": ERROR: unable to open socket: $!\n";
			return 0; 
		}
	}
	unless( connect(SOCK,$sockAddr) ) 
	{ 
		print STDOUT getTime().": ERROR: unable to connect socket: $!\n";
		return 0; 
	}

	select(SOCK); $| = 1; # quick select to set default file handle and make it autoflush
	if ($loggerOn) { system("$logger [tail2syslog][".$options{c}."] successfully connected to ".$host.":".$port) };

	return *SOCK{IO};
}

sub dropAll()
{
	foreach my $sock (@sockets)
	{
		disconnectMe($sock);
	}
	undef(@sockets);
}

sub disconnectMe($)
{
	(my $socket) = @_;
	if( $socket )
	{
		if (!close($socket)) 
		{
			 print STDOUT getTime().": ERROR: Unable to close socket: $!\n";
		}
	}
	if ($loggerOn) { system("$logger [tail2syslog][".$options{c}."] disconnecting") };
}

sub startDaemon($$$)
{
	(my $execName, my $lockFile, my $pidFile) = @_;
	
	# Get ready to daemonize by redirecting our output to syslog, requesting that logger prefix the lines with our program name:
	$| = 1; # Make output line-buffered so it will be flushed to syslog faster
	
	chdir('/'); # Avoid the possibility of our working directory resulting in keeping an otherwise unused filesystem in use
	
	# Double-fork to avoid leaving a zombie process behind:
	exit if (fork());
	exit if (fork());
	sleep 5;
	
	# write the daemonized pid to pidfile for init script control
	open(PIDFILE,">$pidFile");
	print PIDFILE "$$\n";
	close(PIDFILE);
	
	if ($loggerOn) { system("$logger [tail2syslog][".$options{c}."] $execName $$ successfully daemonized") };
}

sub stopDaemon($$)
{
	(my $lockFile, my $pidFile) = @_;
	unlink $lockFile;
	unlink $pidFile;
}

# given a globbing pattern, finds the most-recently modified matching file.
# returns the file name (string) of the found file.
sub getLatest($)
{
	my $globule = shift;
	my @files = bsd_glob($globule);
	my @sortedfiles = reverse sort {stat($a)->mtime() <=> stat($b)->mtime()} @files;
	chomp(@sortedfiles);
	my $maxTime = 0;
	my $foundFile = "";
	my $oldFile = "";

	# If the sort brings back more than 1 file matching the glob, then we should archive
	# everything except the first file. Because this method is called consistently to 
	# monitor file roll overs, we don't need to move/archive all old files in one go,
	# we can just do it iteratively as we come through here by moving/archiving the last
	# file in the list. This also guarantees that newest files will persist in the archive
	# directory, even if we startup the script with lots of old files matching the globs
	# in the globs' directory.
	if (scalar(@sortedfiles) >= 2)
	{
		$foundFile = $sortedfiles[0];
		$oldFile = $sortedfiles[scalar(@sortedfiles)-1];

		if ( -f $oldFile)
		{
			if ($thresh)
			{
				zipAndDelete($oldFile, $globule);
			}
		}
	}
	elsif (scalar(@sortedfiles) == 1) 
	{
		$foundFile = $sortedfiles[0];
	}

	if ($oldFile ne "")  
	{
		if ($loggerOn) { system("$logger [tail2syslog][".$options{c}."] Currently monitoring $foundFile") };
	}
	$foundFile
}

# when a file rolls over, we want to move the file that is full.
# also, we want to zip it up and delete the non-zipped copy
sub zipAndDelete($$)
{
	my $oldFile = shift;
	my $glob = shift;

	my($filename, $directories) = fileparse($oldFile);
        if(!move($oldFile, $archive))
	{
		print STDOUT getTime().": ERROR: could not move file '$archive$filename'.\n";
	}

        chdir($archive);
        system("$tar $taropts $filename$tarSuffix $filename");

	# If we successfully created the archive, then delete the non-archived file.
	# without this check it would be possible to fail to create the archive, then
	# immediately delete the non-archived version, leaving nothing behind at all.
	if (-e "$filename"."$tarSuffix")
	{
		if(!unlink($archive.$filename))
		{
			print STDOUT getTime().": ERROR: could not delete file '$archive$filename'.\n";
		}
	}
	else
	{
		print STDOUT getTime().": ERROR: unable to create archive '$filename$tarSuffix'.\n";
	}
	chdir($workingDir);


	deleteOldArchives($glob);
}

# If there are more archived files than desired in the archive directory
# delete the older files matching the globbing pattern we are using
sub deleteOldArchives($)
{
	my $glob = shift;
	(my $name, my  $dir) = fileparse($glob);

	chdir($archive);
	
	# Grab all archived files matching the glob
	my @files = <$name$tarSuffix>;

	# If the number of files has exceeded the threshold, we need to get
	# a listing of the files in order of age, deleting the oldest ones
	# to get below the threshold.
	if (scalar(@files) > $thresh)
	{
		# sort the files in order of modification date, oldest files last
		my @sortedFiles = reverse sort {stat($a)->mtime() <=> stat($b)->mtime()} @files;
		chomp(@sortedFiles);
		
		# Delete everything beyond the threshold
		for (my $i = $thresh; $i < scalar(@sortedFiles); $i++)
		{
			if ($loggerOn) { system("$logger [tail2syslog][".$options{c}."] Deleting old archive $sortedFiles[$i].") };
			if(!unlink($sortedFiles[$i]))
			{
				print STDOUT getTime().": ERROR: unable to delete archive $sortedFiles[$i].\n";
			}
		}
	}
	chdir($workingDir);
}

# given a list of globbing patterns, builds a corresponding list of functions,
# each is a wrapped version of getLatest($) that passes the single globbing
# pattern as an arguement. The idea is that this results in one no-argument
# function per globbing pattern. no-arg functions can then be used as
# callbacks in the File::Tail package.
sub createSubs(@)
{
	my @subs = ();
	my @argz = @_;
	for( my $i = 0; $i<scalar(@argz); $i++ )
	{
		my $globParm = eval '$argz[$i]';
		push( @subs, sub { getLatest($globParm) } );
	}	
	@subs
}

# creates and populates a list of File::Tail objects, each activated with a
# file globbing routine to stay on top of the latest matching file
sub createTails($)
{
	my $func = shift;
	my @tailz = ();
	my $tail = File::Tail->new(	name=>$func->(),
					name_changes=>$func,
					tail=>1,
					reset_tail=>-1,
					maxinterval=>5,
					interval=>1,
					adjustafter=>5,
					resetafter=>5,
					ignore_nonexistant=>1
					);
	push(@tailz,$tail);
	@tailz
}

# read the list of globbing patterns from the given file (one per line) and
# return the list
sub createGlobs()
{
	my @globs = ();
	foreach my $glob (@globlist) 
	{
		chomp($glob);
		push(@globs, $glob);
	}
	@globs
}

my $NEW_TAIL_INTERVAL = 20;
my $startTime = 0;
sub isTimeToGetNewTails()
{
	my $retVal = 0;
	my $now = time;
	my $elapsed = $now - $startTime;
	if($elapsed >= $NEW_TAIL_INTERVAL)
	{
		$retVal = 1;
		$startTime = $now;	
	}
	return $retVal;
}

my %existing = ();
my @tails = ();
#for each glob, see how many files it returns, if that is more than last time, then push a new tail object onto array
sub getTails()
{
	if(isTimeToGetNewTails())
	{
		return @tails;
	}
	my @globs = createGlobs();
	for (my $count = 0; $count < scalar(@globs); $count++)
        {
		my $add = 0;
		my $glob = $globs[$count];
		my @files = <{$glob}>;
		my $numGlobbed = scalar(@files);
		chomp $numGlobbed;
		my $exists = $existing{$glob};
		if(defined($exists))
		{
			if("$numGlobbed" eq "")
			{
				$numGlobbed = 0;
			}
			my $foundNew = ($numGlobbed - $exists) > 0;
			if($foundNew)
			{
				$add = 1;
			}
		}
		else
		{
			$add = 1;
		}
		$existing{$glob} = $numGlobbed;

		if($add)
		{
			my @dynsub = createSubs($glob);
			my @newTails = createTails($dynsub[0]); 	
			my $tail = $newTails[0];

			# Sometimes the tailing function will mistakenly try
			# add files to the tails list when they are already in there.
			my $dup = 0;
			for(my $i = 0; $i < scalar(@tails); $i++)
			{
				# The name of the tail is the name of the file, so if it's already
				# in the tail list, we are already tailing it.	
				if ($tails[$i]->name_changes()->() eq $tail->name_changes()->())
				{
					$dup = 1;
				}
			}		
			
			if ($dup == 0) 
			{
				push(@tails, $tail);
			}
		}
        }
	@tails
}


# set up signal handlers for proper init control
$SIG{HUP}  = sub 
		{ 
			if ($loggerOn) { system("$logger [tail2syslog][".$options{c}."] caught sighup, reset connection") }; 
		 	logLastMessage();	
			$continue = 0; 
		}; # don't exit, just reset connection

$SIG{PIPE} = sub 
		{ 
			if ($loggerOn) { system("$logger [tail2syslog][".$options{c}."] caught sigpipe, reset connection") };
                       	logLastMessage(); 
			$continue = 0; 
		}; # don't exit, just reset connection

$SIG{INT}  = sub 
		{ 
			if ($loggerOn) { system("$logger [tail2syslog][".$options{c}."] caught sigint, exiting") };
                        logLastMessage(); 
			$running = 0; 
		};

$SIG{QUIT} = sub 
		{ 
			if ($loggerOn) { system("$logger [tail2syslog][".$options{c}."] caught sigquit, exiting") };
			logLastMessage();
			$running = 0; 
		};

$SIG{TERM} = sub 
		{ 
			if ($loggerOn) { system("$logger [tail2syslog][".$options{c}."] caught sigterm, exiting") }; 
			logLastMessage();
			$running = 0; 
		};

sub logLastMessage()
{
	if ($currentMessage)
        {
        	if ($loggerOn) { system("$logger [tail2syslog][".$options{c}."] Unable to send message due to service interruption: '".$currentMessage."'") };
	}
}

if( !$options{D} )
{
	startDaemon($execName,$lockFile,$pidFile);
}

# everything above should be fairly generic above this except the command line opts
# the content of this mainloop are all that should need to change for most tail situations
while($running)
{
	
	# If we have a current socket that means we have been interrupted during sending (ecs probably down), in this case we only want to restart
	# the connection that was interrupted, not all of them.
	if ($currentSocket)
	{
		if ($loggerOn) { system("$logger [tail2syslog][".$options{c}."] sigpipe received from ".$currentSocket.", attempting reconnect.") }

		for (my $i = 0; $i < scalar(@sockets); $i++)
		{
			# Remove the socket from our list of sockets			
			if ($socketHash{$currentSocket} eq $sockets[$i])
			{
				if ($loggerOn) { system("$logger [tail2syslog][".$options{c}."] Forgetting old connection to ".$currentSocket) }
				splice(@sockets, $i, 1);
				last;
			}
		}
		
		# Disconnect the socket entirely
		disconnectMe($socketHash{$currentSocket});
		# delete the entry in the hash for the old socket
		delete $socketHash{$currentSocket};
		# attempt to reconnect 
		stubbornReconnect($currentSocket,$options{p},60);
	}
	else #for each destination in the config file, open a socket
	{
		# Just to ensure everything is clean
		dropAll();
		foreach my $con (@iplist)
		{
			if ($loggerOn) { system("$logger [tail2syslog][".$options{c}."] stubborn reconnect called on ".$con) }
			stubbornReconnect($con,$options{p},60);
		}
	}
	if( !$continue )
	{
		next;
	}

	# instantiation of variables needed for the main running loop
	my $syslogPriTag = syslogPri($options{f});
	my $rate = $options{s};	
	my $events = 0;	
	my $start = [ Time::HiRes::gettimeofday( ) ];
	my $startGlob = $start;
	my $elapsed = 0;
        my $elapsedGlob = 0;
	my $destswap = 1;
	my $mod;

	while( $running && $continue )
	{
		my $buf = "";

		# We need the tails to be updated often, but certainly not every run of the loop
		# Limiting the tail refreshing to once every second is a significant improvement
		# on performance.
		$elapsedGlob = Time::HiRes::tv_interval( $startGlob );
                if ($elapsedGlob >= 1)
                {
                        my @tails = getTails();
                        $elapsedGlob = 0;
                        $startGlob = [ Time::HiRes::gettimeofday( ) ];
                }


		(my $nfound,my $timeleft,my @pending) = File::Tail::select(undef,undef,undef,1,@tails);
		unless($nfound)
		{
		}
		else
		{
			foreach(@pending)
			{
				my $msg = "";
				my $name = $execName;
				if( $options{t} )
				{
					$name = basename($_->{"input"});
				}
				$buf = $_->read;
				if( $options{a} )
				{
					my ($sec,$min,$hour,$mday,$mon,$year,$wday,$yday,$isdst)=localtime(time);
					$msg = sprintf("<".$syslogPriTag.">%s %02d %02d:%02d:%02d",$monthMap{sprintf("%02d",$mon+1)},$mday,$hour,$min,$sec);
					$msg = $msg." ".$syslogHost." ".$buf;
				}
				else
				{
					$msg = $buf;
				}
				if( $options{n} )
				{
					$msg = $msg."\n";
				}

				# Sending to multiple dests 
				$mod = $destswap % scalar(@sockets);			

				for my $key (keys %socketHash)
				{
					if ($socketHash{$key} eq $sockets[$mod])
					{
						$currentSocket = $key;
						last;
					}
				}
				
				# Save the current message so that if we receive some interruption we can atleast log the fact that
				# this message was processed, but we could not send it.
				$currentMessage = $msg;
	
				syswrite($sockets[$mod],$msg,length($msg));

				$currentMessage = 0;
				$destswap++;				
				$events = $events + 1;

				# EPS Throttling
				$elapsed = Time::HiRes::tv_interval( $start );
				if ($elapsed >= 1)
				{
					$start = [ Time::HiRes::gettimeofday( ) ];
					$events = 0;
				}
				if ($events >= $rate)
				{	
					my $sleeptime = 1 -  $elapsed;
					sleep($sleeptime);
					$events = 0;
					$start = [ Time::HiRes::gettimeofday( ) ];	
				}
			}
		}
	}
}

if( !$options{D} )
{
	stopDaemon($lockFile,$pidFile);
}

exit(0);
