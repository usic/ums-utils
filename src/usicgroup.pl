#!/usr/bin/perl -w
# unified script for adding, modifying, deleting, searching user groups in USIC userbase
# author: sakib@meta.ua
# USIC,2008
#
# http://wiki.usic.org.ua/wiki/UMS_utilities
#
# VERSION 0.2

use strict;
use warnings;
use Sys::Syslog qw(:standard :macros);

use lib qw( . /opt/usic/include/ );
use Buscr;
my $rootdn = "";
my $ldap_password="";
my $ldap_port=getservbyname("ldap", "tcp") || "389";
my $debug_level=0;
my $result = 0;
my ($action, $name, @params) = @ARGV;
my $searchobj = 0;

my $cfg_file =  $ENV{USIC_CONF} || "/opt/usic/etc/config";
openlog("UMS:usicgroup", "ndelay,pid", LOG_USER);

if ( &parse_cfg_file_params($cfg_file) ){
	syslog(LOG_ERR, "%s\n", &get_error_descr() );
	exit &exit_code("PARSE");
	}

my $ldap_server = &get_cfg_file_params('server');

# fall back to keep backward compatibility
$ldap_server ="dirs.usic.lan" unless $ldap_server;

my $ldap = new Net::LDAP( $ldap_server, port => $ldap_port, debug => $debug_level);
$result = $ldap->bind($rootdn, password => $ldap_password);

if ($result->code()){
	syslog(LOG_ERR,"could not bind to server %s on port %d : %s\n", $ldap_server, $ldap_port, $result->error_text());	
	exit &exit_code("BIND");
	}

unless (defined $action){
	syslog(LOG_ERR,"too few arguments given\n");
	exit &exit_code("PARSE");
	}

if ($action eq "add"){
	unless (defined $name){
		syslog(LOG_ERR, "error parsing parameters: unspecified group name\n");
		exit &exit_parse("PARSE");
		}
	my @usernames = @params;
	# if we wanted to add users to existing group...
	if ( keys %{&get_group($ldap,$name) } ){
		unless (@usernames){
			syslog(LOG_ERR, "group %s already exists\n", $name);
			exit &exit_code("YES_ENTRY");
			}
		foreach (@usernames){
			unless (keys %{ &get_user($ldap, $_)} ) {
				syslog(LOG_ERR,"Invalid user %s. Skipping.\n", $_);
				next;
				}
			if ( check_user($ldap,$name,$_) == &exit_code("SUCCESS") ){
				syslog(LOG_ERR,"User %s already in group %s. Skipping.\n", $_, $name);
				next;
				}
			if ( &push_user($ldap,$name,$_) ){
				syslog(LOG_ERR, "%s\n", &get_error_descr() );
				exit &get_error_code();
				}
			syslog(LOG_INFO, "added user %s to group %s\n", $_, $name);
			}
		}
	# if we wanted new group...
	else {
		# if we wanted new empty group...
		if ( &add_group($ldap, $name) ){
			syslog(LOG_ERR, "%s\n", &get_error_descr() );
			exit &get_error_code();
			}
		# if we wanted first user in newly created group...
		foreach ( @usernames ){
			unless (keys %{ &get_user($ldap, $_)} ) {
				syslog(LOG_ERR,"Invalid user %s. Skipping.\n", $_);
				next;
				}
			if ( &push_user($ldap,$name,$_) ){
				syslog(LOG_ERR, "%s\n", &get_error_descr() );
				syslog(LOG_ERR,"error adding user %s to group %s\n", $_, $name);
				exit &get_error_code();
				}
			syslog(LOG_INFO, "added user %s to group %s\n", $_, $name);
			}
		}
	}
elsif ($action eq "remove" ){
	unless (defined $name){
		syslog(LOG_ERR, "error parsing parameters: unspecified group name\n");
		exit &exit_code("PARSE");
		}
	unless ( keys %{&get_group($ldap,$name) } ){
		syslog(LOG_ERR, "group %s does not exists\n", $name);
		exit &exit_code("NO_ENTRY");
		}
	my @usernames = @params;
	if (@usernames) {
		foreach (@usernames){
			if ( &pop_user($ldap,$name,$_) ){
				syslog(LOG_ERR, "%s\n", &get_error_descr() );
				syslog(LOG_ERR,"error deleting user %s from group %s\n", $_, $name);
				exit &get_error_code();
				}
			syslog(LOG_INFO, "removed user %s from group %s\n", $_, $name);
			}
		}
	else {
		if ( &remove_group($ldap,$name) ){
			syslog(LOG_ERR, "%s\n", &get_error_descr() );
			syslog(LOG_ERR,"error deleting group %s\n",$name);
			exit &get_error_code();
			}
		syslog(LOG_INFO, "removed group %s\n",$name);
		}
	}

elsif ($action eq "rename" ){
	unless (defined $name){
		syslog(LOG_ERR, "error parsing parameters: unspecified group name\n");
		exit &exit_code("PARSE");
		}
	my $new_name = shift @params;
	unless (defined $new_name){
		syslog(LOG_ERR, "error parsing parameters: unspecified new group name\n");
		exit &exit_code("PARSE");
		}
	unless (keys %{&get_group($ldap,$name)} ) {
		syslog(LOG_ERR, "error parsing parameters: no such group %s\n", $name);
		exit &exit_code("NO_ENTRY");
		}
	if (keys %{&get_group($ldap, $new_name)}) {
		syslog(LOG_ERR, "error parsing parameters: name %s already in use\n", $new_name);
		exit &exit_code("YES_ENTRY");
		}
	$result = $ldap->moddn("cn=$name ," . &get_cfg_file_params('baseDN'),
				newrdn => "cn=$new_name",
				deleteoldrdn => 1
				);
	if ($result->code()){
		syslog(LOG_ERR,"%s\n", $result->error_text());
		exit &exit_code("REQUEST");
		}
	syslog(LOG_INFO, "changed group name %s to %s\n", $name, $new_name);
	}

elsif ($action eq "regid" ){
	unless (defined $name){
		syslog(LOG_ERR, "error parsing parameters: unspecified group name\n");
		exit &exit_code("PARSE");
		}
	my $new_gid = shift @params;
	if ( &search($ldap,"(& (objectClass=posixGroup) (gidNumber=$new_gid))") ){
		syslog(LOG_ERR, "error changing group ID: %d already in use\n", $new_gid);
		exit &exit_code("YES_ENTRY");
		}
	$result = $ldap->modify("cn=$name ," . &get_cfg_file_params('baseDN'),
				replace => { 'gidNumber' => $new_gid }
				);
	if ($result->code()){
		syslog(LOG_ERR,"%s\n", $result->error_text());
		exit &exit_code("REQUEST");
		}
	syslog(LOG_INFO, "changed ID of group %s to %d\n", $name, $new_gid);
	}

elsif ($action eq "show"){
	unshift @params, $name if defined $name;
	my $filter;
	if (@params){
		$filter = '(& (objectClass=posixGroup) (|';
		foreach (@params){
			unless (keys %{&get_group($ldap, $_) }) {
				syslog(LOG_ERR, "unknown group %s. Skipping.\n", $_);
				}
			$filter .= " (cn=$_)";
			}
		$filter .= ' ) )';
		$result = $ldap->search(base => &get_cfg_file_params('baseDN'), scope => 'sub', filter => $filter);
		while ($_ = $result->shift_entry()){
			print $_->get_value('cn'),":\n\t";
			print join("\n\t", $_->get_value('memberUid'));
			print "\n";
			}
		}
	else {
		$filter = '(objectClass=posixGroup)';
		$result = $ldap->search(base => &get_cfg_file_params('baseDN'), scope => 'sub', filter => $filter);
		while ( $_ = $result->shift_entry()){
			print $_->get_value('cn'),"\n";
			}
		}
	}

elsif ($action eq "check" ){
	my $username = shift @params;
	unless (defined $name and defined $username){
		syslog(LOG_ERR, "error parsing parameters: unspecified group or username\n");
		exit &exit_code("PARSE");
		}
	if ( &check_user($ldap,$name,$username) == &exit_code("COMMON") ) {
		syslog(LOG_ERR, "%s\n", &get_error_descr() );
		exit &get_error_code();
		}
	}
else {
	syslog(LOG_ERR, "unknown action: %s . Aborting\n", $action);
	exit &exit_code("PARSE");
	}


$ldap->unbind();
closelog();
exit &exit_code("SUCCESS");
#BYE!
