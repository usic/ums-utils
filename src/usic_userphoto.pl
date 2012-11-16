#!/usr/bin/perl -w
# manage jpegPhoto attribute of USIC accounts
# usage:
# usic_userphoto <set|get> <username> [< <file>]
#
# set: binary JPEG data from stdin stored in jpegPhoto attribite *in binary form*
# 	if stdin empty, jpegPhoto attribute is deleted
# get: binary JPEG data printed to stdin
#
# examples:
# usic_userphoto set sakib < face.jpg
# usic_userphoto get sakib > face.jpg
# usic_userphoto get sakib | base64
# usic_userphoto set sakib < /dev/null (remove photo from LDAP)
#
# author: sakib@meta.ua
# USIC, 2012
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

my $rootdn = "";
my $ldap_password="";
my $ldap_port=getservbyname("ldap", "tcp") || "389";
my $debug_level=0;
my $result = 0;
my ($action,$user) = @ARGV;;

my $cfg_file =  $ENV{USIC_CONF} || "/opt/usic/etc/config";
openlog("UMS:usic_userphoto", "ndelay.pid", LOG_USER);

if ( &parse_cfg_file_params($cfg_file) ){
	syslog(LOG_ERR, "%s\n", &get_error_descr() );
	exit &exit_code("PARSE");
	}

my $ldap_server = &get_cfg_file_params('server');

my $ldap = new Net::LDAP( $ldap_server, port => $ldap_port, debug => $debug_level);
$result = $ldap->bind($rootdn, password => $ldap_password);

if ($result->code()){
	syslog(LOG_ERR,"could not bind to server %s on port %d : %s\n", $ldap_server, $ldap_port, $result->error_text());
	exit &exit_code("BIND");
}

$result = $ldap->search(base => &get_cfg_file_params('baseDN'),
			scope => 'sub',
			filter => "(& (objectClass=posixAccount) (uid=$user))");

if ( $result->code() ){
	syslog(LOG_ERR, "%s\n", $result->error_text());
	exit &exit_code("REQUEST");
}

my $entry = $result->shift_entry();

if ($action =~ /set/){
	my $photo_data;
	while (<STDIN>) {
		$photo_data .= $_;
	}
	unless (defined $photo_data) {
		$entry->delete('jpegPhoto');
	} else {
		$entry->replace( 'jpegPhoto', $photo_data );
	}
	$result = $entry->update($ldap);
	if ( $result->code() ){
		syslog(LOG_ERR, "%s\n",$result->error_text());
		exit &exit_code("REQUEST");
	}
} elsif ($action =~ /get/){
	print $entry->get_value('jpegPhoto');
} else {
	syslog(LOG_ERR, "unknown action: '%s'\n", $action);
	exit &exit_code("PARSE");
}

$ldap->unbind();
closelog();
exit 0;
