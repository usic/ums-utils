#!/usr/bin/perl -w
# unified script for adding, modifying, deleting, searching users in USIC userbase
# author: sakib@meta.ua
# USIC,2008
#
# http://wiki.usic.org.ua/wiki/UMS_utilities
#
# VERSION 0.5 beta

use strict;
use warnings;
use Sys::Syslog qw(:standard :macros);

use lib qw( . /opt/usic/include/);
use Buscr;

my $rootdn = "";
my $ldap_password="";
my $ldap_server="dirs.usic.lan";
my $ldap_port=getservbyname("ldap", "tcp") || "389";
my $debug_level=3;
my $result = 0;
my $action = $0;
my $exit_code = &exit_code("SUCCESS");
my $cfg_file = $ENV{USIC_CONF} || "/opt/usic/etc/config";
my $userhome_top = $ENV{USIC_HOME} || "/usichomes";
openlog("UMS:usic_usermod", "ndelay,pid", LOG_USER);

# SHOWTIME!!!
if ( &parse_cfg_file_params($cfg_file) ){
	syslog(LOG_ERR, "%s\n", &get_error_descr() );
	exit &exit_code();
	}

my $ldap = new Net::LDAP( $ldap_server, port => $ldap_port, debug => $debug_level);
$result = $ldap->bind($rootdn, password => $ldap_password);

if ($result->code()){
	syslog(LOG_ERR,"could not bind to server %s on port %d : %s\n", $ldap_server, $ldap_port, $result->error_text());	
	exit &exit_code("BIND");
	}

if ($action =~ /usic_useradd/){
	my $filling = 0xffffff;
	# $face_key -- interface key
	# $base_key -- LDAP field name
	# $base_value -- LDAP field value
	my ($face_key, $base_key,$base_value);
	my %given_params = &get_hash_params();
	my %ldapFields = (
		# ALL object classes
		# person posixAccount inetOrgPerson student teacher worker readerCardUser studentCardUser voipUser
		objectClass => [ qw(person posixAccount inetOrgPerson)],
		# base fields for every user entry
		cn => $filling, 
		sn => $filling,
		givenName => $filling,
		initials => $filling,
		uid => $filling,
		uidNumber => $filling,
		gidNumber => $filling,
		loginShell => $filling,
		homeDirectory => $filling,
		userPassword => $filling
		);
	# first define object classes and ldap fields according to given params
	while (($face_key,$base_value) = each %given_params){
		unless (defined &ldap_val($face_key)){
			syslog(LOG_ERR, "error parsing parameters: unknown parameter %s\n", $face_key);
			exit &exit_code("PARSE");
			}
		if ( $face_key eq 'login'){
			if (keys %{&get_user($ldap, $base_value)} ){
				syslog(LOG_ERR, "error adding user %s : user already exists\n", $base_value);
				exit &exit_code("YES_ENTRY");
				}
			$ldapFields{&ldap_val($face_key)} = $base_value;
			}
		elsif ( $face_key eq 'reader_card_number'){
			push @{$ldapFields{'objectClass'}}, 'readerCardUser';
			$ldapFields{&ldap_val($face_key)} = $base_value;
			if ( &search($ldap, "(& (objectClass=readerCardUser) (".&ldap_val($face_key)."=$base_value) )" ) ){
				syslog(LOG_ERR, "Reader card number $base_value is aleady in use\n");
				exit &exit_code("YES_READER_CARD_NUM");
				}
			}
		elsif ( $face_key eq 'student_card_number'){
			push @{$ldapFields{'objectClass'}}, 'studentCardUser';
			@ldapFields{&ldap_val('student_card_series'), &ldap_val($face_key)} = $base_value =~ /(\X+?)0*(\d+)/;
			if ( &search($ldap, "(&	(objectClass=studentCardUser)
						(".&ldap_val('student_card_series')."=".$ldapFields{&ldap_val('student_card_series')}.")
						(".&ldap_val($face_key)."=".$ldapFields{&ldap_val($face_key)}.") 
						)" )
				){
				syslog(LOG_ERR, "Student card number $base_value is aleady in use\n");
				exit &exit_code("YES_STUDENT_CARD_NUM");
				}
			}
		elsif ( $face_key eq 'passport_number'){
			push @{$ldapFields{'objectClass'}}, 'passportUser';
			@ldapFields{&ldap_val('passport_series'), &ldap_val($face_key)} = $base_value =~ /(\X+?)0*(\d+)/;
			if ( &search($ldap, "(&	(objectClass=passportUser)
						(".&ldap_val('passport_series')."=".$ldapFields{&ldap_val('passport_series')}.")
						(".&ldap_val($face_key)."=".$ldapFields{&ldap_val($face_key)}.") 
						)" )
				){
				syslog(LOG_ERR, "Passport number $base_value is aleady in use\n");
				exit &exit_code("YES_PASSPORT_NUM");
				}
			}
		elsif ( $face_key eq 'class'){
			# if bachelor
			if ($base_value == 0 || $base_value == 1 || $base_value == 2){
				push @{$ldapFields{'objectClass'}},'student';
				@ldapFields{&ldap_val('entry_year'), &ldap_val('profession'), &ldap_val($face_key)} = (($filling)x2, $base_value);
				}
			# if teacher
			elsif ($base_value == 3){
				push @{$ldapFields{'objectClass'}},'teacher';
				$ldapFields{&ldap_val($face_key)} = $base_value;
				}
			# if other employee
			elsif ($base_value == 4){
				push @{$ldapFields{'objectClass'}},'worker';
				$ldapFields{&ldap_val('department')} = $base_value;
				}
			else {
				syslog(LOG_ERR,"unknown class ID: %d\n", $base_value);
				#exit 22;
				}
			}
		else {next;}

		delete $given_params{$face_key};
		}
	# now put values of given base_value to %ldapFields
	while (($face_key,$base_value) = each %given_params){
		unless (defined $ldapFields{&ldap_val($face_key)}) {
			syslog(LOG_ERR, "error parsing parameter %s : it may not be defined for assumed object class\n", $face_key);
			exit &exit_code("PARSE");
			}
		if ( $face_key eq 'password'){
			chomp ($base_value = &enc_md5($base_value));
			}
		$ldapFields{ &ldap_val($face_key) } = $base_value;
		}
	# now put default values got from config file, etc.
	$ldapFields{"loginShell"} = &get_cfg_file_params('defaultLoginShell');
	$ldapFields{"gidNumber"} = &get_cfg_file_params('defaultGID');
	$ldapFields{"homeDirectory"} = &get_cfg_file_params('defaultHomedir') . "/" . $ldapFields{"uid"};
	$ldapFields{"uidNumber"} = &get_free_uid($ldap);
	
	# givenName -- name
	# sn -- second name
	# initials -- middlename :(
	(	$ldapFields{"sn"},
		$ldapFields{"givenName"},
		$ldapFields{"initials"}
	)	= split /\s+/, $ldapFields{ &ldap_val("name") };
	if ( &add_user($ldap, $ldapFields{'uid'},\%ldapFields) ){
		syslog(LOG_ERR, "%s\n", &get_error_descr());
		exit &get_error_code();
		}
	foreach ( &search($ldap, "(& (objectClass=posixGroup) (gidNumber=$ldapFields{'gidNumber'}) )") ){
		next unless defined $_;
		next unless s/\s*cn=(.+?),.*/$1/;
		if ( &push_user($ldap, $_, $ldapFields{'uid'}) ){
			syslog(LOG_ERR, "%s\n", &get_error_descr() );
			syslog(LOG_ERR, "failed to add user %s to group %s\n", $ldapFields{'uid'}, $_);
			$exit_code = &get_error_code();
			next;
			}
		syslog(LOG_INFO, "added user %s to group %s\n", $ldapFields{'uid'}, $_);
		}

	# make userhome with special SUID application 
	if (system "/opt/usic/bin/usic_usersettle -m -p $userhome_top/$ldapFields{'uid'}/  -u $ldapFields{'uidNumber'} -g $ldapFields{'gidNumber'}" ){
		syslog(LOG_ERR, "error making homedir\n");
		$exit_code =  &exit_code("MKDIR");
		}
	syslog(LOG_INFO, "added entry uid=%s,dc=usic,dc=lan\n", $ldapFields{"uid"});
	}

elsif ($action =~ /usic_userdel/){
	my $uname;
	foreach $uname ( &get_list_params() ){
		unless ( keys %{&get_user($ldap, $uname, 'uid')}){
			syslog(LOG_ERR,"error deleting entry: user %s not exists\n", $uname);
			exit &exit_code("NO_ENTRY");
			}
		foreach (&search($ldap,"(& (objectClass=posixGroup) (memberUid=$uname))")){
			next unless defined $_;
			next unless s/\s*cn=(.+?),.*/$1/;
			if ( &pop_user($ldap, $_, $uname) ){
	                        syslog(LOG_ERR, "%s\n", &get_error_descr() );
				syslog(LOG_ERR, "user %s not removed from group %s\n",$uname, $_);
				$exit_code = &get_error_code();
				next;
				}
			syslog(LOG_INFO, "removed user %s from group %s\n", $uname, $_);
			}
		my $result = $ldap->delete("uid=$uname," . &get_cfg_file_params('baseDN'));
		if ( $result->code() ){
			syslog(LOG_ERR, "%s\n", $result->error_text());
			exit &exit_code("REQUEST");
			}
		# remove userhome with special SUID application
		if ( system "/opt/usic/bin/usic_usersettle -r -p $userhome_top/$uname/" ){
			syslog(LOG_ERR, "error deleting user homedir\n");
			$exit_code = &exit_code("RMDIR");
			}
		syslog(LOG_INFO,"user %s deleted\n", $uname);
		}
	}
elsif ($action =~ /usic_userinfo/){
	my ($login, @values, @attrs);
	my %params = &get_hash_params();
	exit &exit_code("PARSE") unless $login = $params{"login"};
	if ($params{"values"}){
		@values = split ',',$params{"values"}; 
		}
	else {
		# default output user information
		@values = qw(name uid gid loginShell);
		}
	foreach (@values){
		if ($_ eq "student_card_number"){
			push @attrs, &ldap_val("student_card_series");
			}
		elsif ($_ eq "passport_number"){
			push @attrs, &ldap_val("passport_series");
			}
		push @attrs,&ldap_val($_) if &ldap_val($_);
		}
	my %ret_par = %{&get_user($ldap, $login, @attrs)};
	unless ( keys %ret_par){
		syslog(LOG_ERR, "user %s not found\n", $login);
		$ldap->unbind();
		exit &exit_code("NO_ENTRY");
		}
	foreach (@values){
		next unless &ldap_val($_);
		$ret_par{&ldap_val($_)} = $ret_par{&ldap_val("student_card_series")} . $ret_par{&ldap_val($_)} 
			if (	$_ eq "student_card_number" and 
				defined $ret_par{&ldap_val("student_card_series")} and 
				defined $ret_par{&ldap_val($_)}
				);
		$ret_par{&ldap_val($_)} = $ret_par{&ldap_val("passport_series")} . $ret_par{&ldap_val($_)} 
			if (	$_ eq "passport_number" and 
				defined  $ret_par{&ldap_val("passport_series")} and 
				defined  $ret_par{&ldap_val($_)}
				);
		if (defined $ret_par{&ldap_val($_)}){
			print $_ , "=" , $ret_par{&ldap_val($_)} , "\n"; 
			}
		else {
			print $_ , "=\n";
			}
		}
	}
elsif ($action =~ /usic_usermod/){
	my %params = &get_hash_params();
	exit &exit_code("PARSE") unless $params{'login'};
	my $uname = delete $params{'login'};
	$result = $ldap->search(	base => &get_cfg_file_params('baseDN'),
					scope => 'sub',
					filter => "(& (objectClass=posixAccount) (uid=$uname))"
					);
	if ( $result->code() ){
		syslog(LOG_ERR, "%s\n", $result->error_text());
		exit &exit_code("REQUEST");
		}

	my $entry = $result->shift_entry();
	my ($face_key,$base_value);
	while (($face_key,$base_value) = each %params){
		unless (defined &ldap_val($face_key)){
			syslog(LOG_ERR, "error parsing parameters: unknown parameter %s\n", $face_key);
			exit &exit_code("PARSE");
			}
		# if value of "UNDEF" given, erase the whole attribute 
		# NB: case of given $face_key=login mentioned above! Not checking it.
		# NB: changing of UID forbidden by the will of sakib
		if ( $base_value eq 'UNDEF' and $face_key ne 'uid'){
		# FIXME:: is this shit really needed? Waiting for request stay commented out...
		# NB: if requested, do not forget to purge corresponding objectClasses along with deleting attrs
		#	$entry->delete( &ldap_val($face_key) => undef );
			}

		# prohibit the identical unifier numbers
		elsif ($face_key eq 'reader_card_number'){
			if ( &search($ldap, "(& (objectClass=readerCardUser) (".&ldap_val($face_key)."=$base_value) )" ) ){
				syslog(LOG_ERR, "Reader card number $base_value is aleady in use\n");
				exit &exit_code("YES_READER_CARD_NUM");
				}
			unless ( $entry->get_value(&ldap_val($face_key)) ){
				$entry->add(	'objectClass' => 'readerCardUser',
						&ldap_val('reader_card_number') => $base_value 
						);
			}else{
				$entry->replace(&ldap_val('reader_card_number') => $base_value);
				}
			}
		elsif ($face_key eq 'student_card_number'){
			$base_value =~ /(\X+?)0*(\d+)/;
			my $series = $1;
			my $number = $2;
			if ( &search($ldap, "(&	(objectClass=studentCardUser)
						(".&ldap_val('student_card_series')."=$series)
						(".&ldap_val('student_card_number')."=$number) 
						)" )
				){
				syslog(LOG_ERR, "Student card number $base_value is aleady in use\n");
				exit &exit_code("YES_STUDENT_CARD_NUM");
				}
			unless ( $entry->get_value(&ldap_val($face_key)) ){
				$entry->add(	'objectClass' => 'studentCardUser',
						&ldap_val('student_card_series') => $series,
						&ldap_val('student_card_number') => $number
						);
			}else{
				$entry->replace(
						&ldap_val('student_card_series') => $series,
						&ldap_val($face_key) => $number
						);
				}
			}
		elsif ($face_key eq 'passport_number'){
			$base_value =~ /(\X+?)0*(\d+)/;
			my $series = $1;
			my $number = $2;
			if ( &search($ldap, "(&	(objectClass=passportUser)
						(".&ldap_val('passport_series')."=$series)
						(".&ldap_val('passport_number')."=$number) 
						)" )
				){
				syslog(LOG_ERR, "Passport number $base_value is aleady in use\n");
				exit &exit_code("YES_PASSPORT_NUM");
				}
			unless ( $entry->get_value(&ldap_val($face_key)) ){
				$entry->add(	'objectClass' => 'passportUser',
						&ldap_val('passport_series') => $series,
						&ldap_val('passport_number') => $number
						);
			}else{
				$entry->replace(
						&ldap_val('passport_series') => $series,
						&ldap_val('passport_number') => $number
						);
				}
			}
		# encode password
		elsif ($face_key eq 'password'){
			chomp($base_value = &enc_md5($base_value));
			$entry->replace(&ldap_val($face_key) => $base_value);
			}
		elsif ($face_key eq 'gid'){
			my $old_gid = $entry->get_value(&ldap_val('gid'));
			# Get list of DNs that have gidNumbers of given gid
			foreach ( &search($ldap,"(& (objectClass=posixGroup) (gidNumber=$base_value) )")){
				# get group name according new gid
				next unless defined $_;
				next unless s/\s*cn=(.+?),.*/$1/;
				if ( &push_user($ldap, $_, $uname) ){
					syslog(LOG_ERR, "%s\n", &get_error_descr() );
					syslog(LOG_ERR, "failed to add user %s to group %s\n", $uname, $_);
					$exit_code = &get_error_code();
					next;
					}
				$entry->replace(&ldap_val($face_key) => $base_value);
				}
			# cleanup user from old group
			foreach (&search($ldap,"(& (objectClass=posixGroup) (gidNumber=$old_gid) )")){
				next unless defined $_;
				next unless s/\s*cn=(.+?),.*/$1/;
				if ( &pop_user($ldap, $_, $uname) ){
					syslog(LOG_ERR, "%s\n", &get_error_descr() );
					syslog(LOG_ERR, "failed to remove user %s from group %s\n", $uname, $_);
					$exit_code = &get_error_code();
					next;
					}
				}
			}
		elsif($face_key eq 'name'){
			my ($surname, $givenname, $middlename) = split /\s+/,$base_value;
			$entry->replace(cn => $base_value, 
					sn => $surname, 
					givenName => $givenname, 
					initials => $middlename
					);
			}
		# changing UID will be done when needed
		# use special request to modify RDN
		#elsif ($face_key eq 'new_login'){
		#	if (keys %{&get_user($ldap,$base_value,'')}){
		#		syslog(LOG_ERR,"user %s already exists\n",$base_value);
		#		exit &exit_code("YES_ENTRY");
		#		}
		#	$entry->replace('uid' => $base_value);
		#	$result = $entry->update($ldap,'moddn');
		#	if ( $result->code() ){
		#		syslog(LOG_ERR, "%s\n",$result->error_text());
		#		exit &exit_code("REQUEST");
		#		}
		#	next;
		#	}
		#
		# never change UID
		elsif ($face_key eq 'uid'){
			syslog(LOG_INFO,"changind UID is forbidden (sakib)\n");
			next;
			}
		# TODO check if key is valid
		# all the rest no matter
		else {
			$entry->replace( &ldap_val($face_key) => $base_value );
			}
		}
	$result = $entry->update($ldap);
	if ( $result->code() ){
		syslog(LOG_ERR, "%s\n",$result->error_text());
		exit &exit_code("REQUEST");
		}
	}

$ldap->unbind();
closelog();
exit $exit_code;
#BYE!
