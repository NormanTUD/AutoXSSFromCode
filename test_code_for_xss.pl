#!/usr/bin/perl

=head
IDEA:

This script searches through a source-code tree and finds variable names for
$_GET- and $_POST-requests. That is, it finds possible things that output
directly to the website. After this is done, the script automatically searches
through a URL (usually on localhost) for user inputs that show up on the page
unvalidatedly.

This allows automatically checking for vulnerable pages that print out user's
inputs without any validation.

USAGE:

Set
my $startpage = "http://localhost/";
to your local webhost-folder that should be searched.

Also, set
my $codepath = "/path/to/source_code_folder/";
for the path where your source code is.

CAVEATS:

I use two functions, namely, get_get("varname") and get_post("varname") for getting
GET and POST parameters. This is easier to write than $_GET['varname'], looks better
and allows possible wrapper functionalities easily. These PHP-functions are not provided,
but you can easily make them yourself.

Instead of just searching for $_GET and $_POST, this script automatically also
searches for get_get("..") and get_post("...").

It does not search for $_GET[$varname], though, since this cannot easily be achieved
through static code analysis, but would need the program to run.

=cut

use strict;
use warnings;
use LWP::UserAgent;
use Data::Dumper;
use URI::Encode qw/uri_encode/;
use List::MoreUtils qw(uniq);
use Term::ANSIColor;

my $ua = LWP::UserAgent->new;

my $startpage = "http://localhost/";
my $codepath = "/path/to/source_code_folder/";

main($startpage, $codepath);

sub main{

	my $startpage = shift;
	my $path = shift;
	my @get_values = get_possible_get_variables($path);
	my @post_values = get_possible_post_variables($path);

	create_request(startpage => $startpage, get => \@get_values, post => \@post_values);
}

sub get_xss_codes {
	my @codes = ();
	while (<DATA>) {
		chomp;
		push @codes, $_;
	}
	return @codes;
}

sub create_request {
	my %params = (
		startpage => undef,
		get => {},
		post => {},
		@_
	);

	my @xss_codes = get_xss_codes();

	my $i = 0;
	my $gesamt = scalar(@xss_codes) * scalar(@{$params{get}}) * scalar(@{$params{post}});
	my @injections_found = ();

	foreach my $this_xss_code (@xss_codes) {
		foreach my $this_get (sort { $a cmp $b } @{$params{get}}) {
			foreach my $this_post(sort { $a cmp $b } @{$params{post}}) {
				my @request_params = ($params{startpage}, { post => { $this_post => $this_xss_code }, get => { $this_get => $this_xss_code } });
				my ($is_success, $decoded_content, $status_line) = make_request(@request_params);

				if(!$is_success) {
					warn "ERROR: cannot call $params{startpage}, $status_line!\n\n";
				}

				if($decoded_content =~ m#\Q$this_xss_code\E#) {
					my $str = color("red")."ERROR: Injection found for\n".Dumper(@request_params)."\n!!!!!!!".color("reset")."\n";

					push @injections_found, $str;
					warn $str;
				}
				$i++;
				print "Done $i of $gesamt (".sprintf("%.2f", ($i / $gesamt) * 100).")%\n";
			}
		}
	}

	if(@injections_found) {
		print "Injections found: ";
		foreach (@injections_found) {
			print "$_\n";
		}
	}
}

sub get_possible_post_variables {
	my $startpath = shift;
	my $type = 'POST';
	return get_possible_variables($startpath, $type);
}

sub get_possible_get_variables {
	my $startpath = shift;
	my $type = 'GET';
	return get_possible_variables($startpath, $type);
}

sub get_possible_variables {
	my $startpath = shift;
	my $type = shift;
	my @get_values = ('');

	my @files = get_files($startpath);

	my $q1 = "get_get";
	my $q2 = "_GET";

	if($type eq 'POST') {
		$q1 = "get_post";
		$q2 = "_POST";
	}

	foreach my $this_file (@files) {
		open my $fh, '<', $this_file;
		my $code = '';
		while (my $this_line = <$fh>) {
			$code .= $this_line;
		}
		close $fh;

		while ($code =~ m#$q1\(("|')([^\)]+?)\1\)#g) {
			push @get_values, $2;
		}

		while ($code =~ m#\$$q2\[("|')([^\)]+?)\1\]#g) {
			push @get_values, $2;
		}
	}

	@get_values = uniq(@get_values);

	return @get_values;
}

sub get_files {
	my $startpath = shift;

	my @files = ();

	my $dirhandle = undef;
	if(!opendir $dirhandle, $startpath) {
		warn "$startpath could not be found!";
	}
	while (my $file = readdir($dirhandle)) {
		next if $file =~ m#^\.{1,2}$#;
		if(-d "$startpath/$file") {
			push @files, get_files("$startpath/$file");
		}

		if($file =~ m#\.php$#) {
			push @files, "$startpath/$file";
		}
	}
	close $dirhandle;

	return @files;
}

sub make_request {
	my $url = shift;
	my $params = shift;

	my @get_parameters = ();
	#die Dumper $params;
	foreach my $item (keys %{$params->{get}}) {
		push @get_parameters, $item.'='.uri_encode($params->{get}->{$item});
	}

	my $url_parameters = join('&', @get_parameters);

	my $full_url = $url.'?'.$url_parameters;

	warn "Trying ... $full_url\n".Dumper($params->{post})."\n";

	my $res = $ua->post($full_url, $params->{post});

	my ($is_success, $decoded_content , $status_line) = ($res->is_success, $res->decoded_content, $res->status_line);

	return ($is_success, $decoded_content, $status_line);
}
__DATA__
<script type="text/javascript">alert(1);</script>
