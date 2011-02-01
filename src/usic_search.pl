#!/usr/bin/perl -w
# Searching LDAP accounts that match specified criteria
# author: sakib@meta.ua
# USIC, 2011
#
# http://wiki.usic.org.ua/wiki/UMS_utilities
#
# VERSION 0.1
#

use strict;
use warnings;
use  Sys::Syslog qw(:standard :macros);

use lib qw( . /opt/usic/include/ );
use Buscr;

my $rootdn = "cn=elfy,dc=usic,dc=lan";
my $ldap_password="Ahcaj7ee";
my $ldap_server="dirs.usic.lan";
my $ldap_port=getservbyname("ldap", "tcp") || "389";
my $debug_level=0;
my $result = 0;
my @match;

my $cfg_file =  $ENV{USIC_CONF} || "/opt/usic/etc/config";
openlog("UMS:usic_search", "ndelay.pid", LOG_USER);

if ( &parse_cfg_file_params($cfg_file) ){
	syslog(LOG_ERR, "%s\n", &get_error_descr() );
	exit &exit_code("PARSE");
	}

my $ldap = new Net::LDAP( $ldap_server, port => $ldap_port, debug => $debug_level);
$result = $ldap->bind($rootdn, password => $ldap_password);

if ($result->code()){
	syslog(LOG_ERR,"could not bind to server %s on port %d : %s\n", $ldap_server, $ldap_port, $result->error_text());
	$result = "BIND";
	goto EXIT;
}

my %args = &get_hash_params();
my ($arg, $pattern, $key,$request);

unless (keys %args){
	$result = "SUCCESS";
	goto EXIT;
}

$request = "(& (objectClass=posixAccount) ";
while ( ($arg, $pattern) = each %args){
	$key = &ldap_val($arg);
	unless ( defined $key ){
		syslog(LOG_ERR, "error parsing parameters: unknown parameter %s\n", $arg);
		$result = "PARSE";
		goto EXIT;
	}
	$request .= "(".$key."=".$pattern.") ";
}

$request .= ")";

@match = &get_entry($ldap, $request, 'uid');
if (@match){
	foreach (@match){
		print $_->{'uid'}, "\n";
	}
	$result = "SUCCESS";
} else {
	if ($result = &get_error_code()){
		syslog(LOG_ERR, "%s\n", &get_error_descr());
	} else {
		$result = "NO_ENTRY";
	}
}

EXIT:
$ldap->unbind();
closelog();
exit &exit_code($result);
#BYE!
#
