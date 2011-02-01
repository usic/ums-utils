############################################################################
#    Copyright (C) 2008 by Sergiy Kibrik   #
#    sakib@meta.ua   #
#                                                                          #
#    This program is free software; you can redistribute it and#or modify  #
#    it under the terms of the GNU General Public License as published by  #
#    the Free Software Foundation; either version 2 of the License, or     #
#    (at your option) any later version.                                   #
#                                                                          #
#    This program is distributed in the hope that it will be useful,       #
#    but WITHOUT ANY WARRANTY; without even the implied warranty of        #
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the         #
#    GNU General Public License for more details.                          #
#                                                                          #
#    You should have received a copy of the GNU General Public License     #
#    along with this program; if not, write to the                         #
#    Free Software Foundation, Inc.,                                       #
#    59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.             #
############################################################################

package Buscr;
use strict;
use warnings;
require Net::LDAP;
require Net::LDAP::Entry;

require Exporter;
our @ISA = ("Exporter");
our @EXPORT = qw(check_user
		exit_code
 		get_cfg_file_params
		get_error_code
		get_error_descr
		get_group
		get_user
		get_entry
		ldap_val
		get_hash_params
		get_list_params
		parse_cfg_file_params
		search
		add_group
		add_user
		enc_md5
		get_free_uid
		get_free_gid
		pop_user
		push_user
		remove_group
		);
# defined subroutine error code
my $error_code = undef;

# defined short text description of LDAP request failure
my $error_descr = undef;

# defined exit codes of scripts
my %exit_code = (
	SUCCESS => 0,
	NOT_IN_GROUP => 1,
	BIND => 11,
	REQUEST => 15,
	MKDIR => 21,
	PARSE => 22,
	RMDIR => 23,
	COMMON => 31,
	NO_ENTRY => 32,
	YES_ENTRY => 33,
	YES_READER_CARD_NUM => 34,
	YES_STUDENT_CARD_NUM => 35,
	YES_PASSPORT_NUM => 36
	);


# global user parameters hold in config file
# FORMAT: 
# [UMS]
# key=value
# ...
# [/UMS]

my %cfg_file_params = (
	# [UMS]
	defaultGID => "gidNumber",
	defaultLoginShell => "loginShell",
	defaultHomedir => "homeDirectory",
	baseDN => "basedn"
	# [/UMS]	
	);

#########################################
# SUBROUTINES
#########################################

# parse configuration file
sub parse_cfg_file_params {
	my $conf_file =  shift;
	unless ( open(CONF,"$conf_file") ){
		$error_descr = "failed to open configuration file $conf_file";
		$error_code = &exit_code("PARSE");
		return &exit_code("COMMON");
		}
	my @config = <CONF>;
	while (@config){
		chomp($_ = shift @config);
		if (/^\[UMS\]$/){
			while ($_ = shift(@config)){
				next if /^#.*/;
				last if /^\[\/UMS\]$/;
				next unless /\s*(\w+)="?(.+?)"?$/;
				if (defined $cfg_file_params{$1}) {
					$cfg_file_params{$1} = $2;
					}
				else {
					$error_descr = "error parsing perameters from config file: $1 unknown parameter";
					$error_code = &exit_code("PARSE");
					return &exit_code("COMMON");
					}
				}
			}
		}
	close(CONF);
	return &exit_code("SUCCESS");
	}

# returns corresponding configuration parameter value
# do parse_cfg_file_params() before calling !!
sub get_cfg_file_params {
	return $cfg_file_params{$_[0]};
	}

# returns last error operation description
sub get_error_descr {
	if (defined $error_descr){
		chomp $error_descr;
		return &clear_descr()."\n";
		}
	return "All done!\n";
}

# cleans up last error description
sub clear_descr {
	my $old_descr = $error_descr;
	$error_descr = undef;
	return $old_descr;
	}
# gets last subroutine error code
sub get_error_code {
	return $error_code;
	}

# just return error numcode
sub exit_code {
	return $exit_code{$_[0]};
	}

# having hash simply adds it's values to proper place in LDAP
sub add_user {
	my ($ldap, $uname, $params) = @_;
	unless ( defined($ldap) and defined($uname) and defined($params) ) {
		$error_descr = "add_user(): too few arguments given";
		$error_code = &exit_code("PARSE");
		return &exit_code("COMMON");
		}	
	my $dn = 'uid=' . $uname . ',' . &get_cfg_file_params('baseDN');
	my $entry = Net::LDAP::Entry->new($dn);
	$entry->replace(%$params);
	my $return = $ldap->add($entry);
	if ( $return->code() ){
		$error_descr = $return->error_text();
		$error_code = &exit_code("REQUEST");
		return &exit_code("COMMON");
		}
	return &exit_code("SUCCESS");
	}

# get hash of parameters from STDIN
sub get_hash_params {
	my %plist;
	while (<STDIN>){
		next unless /\s*(\w+)=(.+)/;
		chomp($plist{$1} = $2);
		}
	return %plist;
	}

# get list of parameters from STDIN
sub get_list_params {
	my @plist;
	while (<STDIN>){
		next unless $_;
		chomp $_;
		push @plist,$_;
		}
	return @plist;
	}

#sub get_salt {
#        my $salt = join '', ('a'..'z')[rand 26,rand 26,rand 26,rand 26,rand 26,rand 26,rand 26,rand 26];
#        return($salt);
#}
# encode given password using SSHA algorithm
#sub enc_ssha(){
#	use Digest::SHA1;
#       use MIME::Base64;	
#	my $pass = shift;
#       my ($hashedPasswd,$salt);
#	$salt = &get_salt();
#       my $ctx = Digest::SHA1->new;
#       $ctx->add($pass);
#	$ctx->add($salt);
#       $hashedPasswd = '{SSHA}' . encode_base64($ctx->digest . $salt);
#       return($hashedPasswd);
#	}

# encode user password in MD5
sub enc_md5 {
        my $pass= shift;
        use Digest::MD5;
        use MIME::Base64;
        my ($hashedPasswd);
        my $ctx = Digest::MD5->new;
        $ctx->add($pass);
        $hashedPasswd = '{MD5}' . encode_base64($ctx->digest);
        return $hashedPasswd;
}

# get LDAP field referring given interface parameter
sub ldap_val {
	my $key = shift;
	my %interface_params = (
		login => "uid",
	#	new_login => "uid",
		password => "userPassword",
		name => "cn",
		uid => "uidNumber",
		gid => "gidNumber",
		profession => "faculty",
		class => "profession",
		reader_card_number => "readerCardNumber",
		student_card_number => "studentCardNumber",
		passport_number => "passportNumber",
		student_card_series => "studentCardSeries",
		passport_series => "passportSeries",
		department => "department",
		entry_year => "yearOfEntry",
		loginShell => 'loginShell',
		home => 'homeDirectory'
		);
	return $interface_params{$key};
	}

# select entries from LDAP, which names is hold in @attrs
# returns hash giving accordance between requested field name & it's value
sub get_group {
	my ($ldap,$gname, @attrs) = @_;
	my @ents = &get_entry($ldap, "(& (objectClass=posixGroup) (cn=$gname))", \@attrs);
	return $ents[0] if defined $ents[0];
	return {};
	}
sub get_user {
	my ($ldap, $login, @attrs) = @_;
	my @ents = &get_entry($ldap, "(& (objectClass=posixAccount) (uid=$login))", \@attrs);
	return $ents[0] if defined $ents[0];
	return {};
	}

sub add_group {
	my ($ldap, $gname) = @_;
	my $result = $ldap->add(
			"cn=".$gname.",".&get_cfg_file_params('baseDN'),
			attrs => [
				objectClass => "posixGroup",
				gidNumber => &get_free_gid($ldap),
				cn => $gname
				]
		);
	if ( $result->code() ){
		$error_descr = $result->error_text();
		$error_code = &exit_code("REQUEST");
		return &exit_code("COMMON");
		}
	return &exit_code("SUCCESS");
	}

sub push_user {
	my ($ldap, $gname, $uname) = @_;
	my $result = $ldap->modify(
				"cn=".$gname.",".&get_cfg_file_params('baseDN'),
				add => { memberUid => "$uname" }
				);
	if ( $result->code() ){
		$error_descr = $result->error_text();
		$error_code = &exit_code("REQUEST");
		return &exit_code("COMMON");
		}
	return &exit_code("SUCCESS");
	}

sub remove_group {
	my ($ldap,$gname) = @_;
	my $result = $ldap->delete("cn=".$gname.",".&get_cfg_file_params('baseDN'));
	if ( $result->code() ){
		$error_descr = $result->error_text();
		$error_code = &exit_code("REQUEST");
		return &exit_code("COMMON");
		}
	return &exit_code("SUCCESS");

	}

sub pop_user {
	my ($ldap,$gname,$uname) = @_;
	my $result = $ldap->modify(
			"cn=".$gname.",".&get_cfg_file_params('baseDN'),
			delete => {memberUid => $uname}
			);
	if ( $result->code() ){
		$error_descr = $result->error_text();
		$error_code = &exit_code("REQUEST");
		return &exit_code("COMMON");
		}
	return &exit_code("SUCCESS");
	}

sub check_user {
	my ($ldap,$gname,$uname) = @_;
	my $result = $ldap->search(base => &get_cfg_file_params('baseDN'), scope => "sub", filter => "(& (memberUid=$uname)(cn=$gname)(objectClass=posixGroup))");
	if ( $result->code() ){
		$error_descr = $result->error_text();
		$error_code = &exit_code("REQUEST");
		return &exit_code("COMMON");
		}
	if ($result->count == 0){
		$error_descr = "error LDAP request: group $gname has not user $uname";
		$error_code = &exit_code("NOT_IN_GROUP");
		return &exit_code("COMMON");
		}
	return &exit_code("SUCCESS");
	}

# return user/group ID numder which is unique in the base. Usually it's the greatest one :)
sub get_free_gid {
	return &get_free_id(shift, "objectClass=posixGroup", "gidNumber");
	}
sub get_free_uid {
	return &get_free_id(shift, "objectClass=posixAccount", "uidNumber");
	}

# return the greatest numeric field of $id_attr among request of $filter
sub get_free_id {
	my ($ldap,$filter,$id_attr) = @_;
	my $searchobj = $ldap->search(base => &get_cfg_file_params('baseDN'), scope => "sub", filter => $filter, attrs => [$id_attr] );
	my @entires = $searchobj->entries();
	my ($max_id, $id) = qw(1000 0);
	foreach (@entires){
		$id = $_->get_value($id_attr);
		$max_id = $id if  $id > $max_id ;
		}
	return ++$max_id;
	}

# get entry according to $filter & return hash if attributes named after \@attrs
sub get_entry {
	my ($ldap, $filter, $attrs) = @_;
	my @result = ();
	unless (defined $ldap or defined $filter){
		$error_descr = "get_entry(): undefined non-optional parameter";
		$error_code = &exit_code("PARSE");
		return @result;
		}
	my %hash_node = ();
	my ($searchobj,$entry);
	if (defined $attrs) {
		$searchobj = $ldap->search(base => &get_cfg_file_params('baseDN'), scope => "sub", filter => $filter, attrs => $attrs);
		}
	else {
		$searchobj = $ldap->search(base => &get_cfg_file_params('baseDN'), scope => "sub", filter => $filter );
		}

	while ( $entry = $searchobj->shift_entry() ){
		$result[$#result + 1]->{'dn'} = $entry->dn();
		foreach ($entry->attributes){
			$result[$#result]->{$_} = $entry->get_value($_);
			}
		}
	$error_code = &exit_code("SUCCESS") unless @result;
	return @result;
	}

sub search {
	my ($ldap, $filter) = @_;
	my @result;
	my @ents = &get_entry($ldap,$filter,'dn' );
	foreach (@ents){
		push @result,$_->{'dn'};
		}
	return @result;
	}
1;
