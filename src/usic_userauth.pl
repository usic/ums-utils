#!/usr/bin/perl -w
# password checking utility, replacement of original usiccheckpasswd shell crap
# usage:
# 	usic_userauth <user>
#
# password read from stdin
# return 0 on valid user & password, error otherwise
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

my $ldap_port=getservbyname("ldap", "tcp") || "389";
my $debug_level=0;
my $result = 0;
my $user = shift;

my $cfg_file =  $ENV{USIC_CONF} || "/opt/usic/etc/config";
openlog("UMS:usic_userauth", "ndelay.pid", LOG_USER);

if ( &parse_cfg_file_params($cfg_file) ){
	syslog(LOG_ERR, "%s\n", &get_error_descr() );
	exit &exit_code("PARSE");
	}

unless (defined $user) {
	syslog(LOG_ERR, "no username supplied\n");
	exit &exit_code("PARSE");
}

my $ldap_server = &get_cfg_file_params('server');
my $base = &get_cfg_file_params('baseDN');
my $dn = "uid=$user,$base";
my $password = <STDIN>;
chomp $password;
my $ldap = new Net::LDAP( $ldap_server, port => $ldap_port, debug => $debug_level);
$result = $ldap->bind($dn, password => $password);

if ($result->code()){
	syslog(LOG_ERR,"could not bind to server %s on port %d : %s\n", $ldap_server, $ldap_port, $result->error_text());
	$result = "BIND";
} else {
	$result = "SUCCESS";
}

$ldap->unbind();
closelog();
exit &exit_code($result);
