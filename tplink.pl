#!/usr/bin/perl

# TP-Link Archer C7 monitoring
# based on
# https://github.com/alext/munin_plugins/blob/master/http__tp_link_wa901nd

use strict;
use warnings;
use Digest::MD5;
use LWP;
use LWP::UserAgent;
use MIME::Base64;
use URI::Escape;

my $user = exists $ENV{'username'} ? $ENV{'username'} : 'admin';
my $pass = exists $ENV{'password'} ? $ENV{'password'} : 'admin';
my $host = exists $ENV{'host'} ? $ENV{'host'} : '192.168.100.222';
my $dbg = ($< == 1000) ? 1 : 0;

# Globals.
my $url_token;
my $auth_cookie;


sub Dbg {
	if ($dbg == 1) {
		my ($text) = @_;
		print "--> $text\n";
	}
}

# 1 - username
# 2 - password
sub build_auth_cookie {
	my ($u, $p) = @_;

	my $md5 = Digest::MD5->new;
	my $hashed_password = $md5->add($p);
	#my $value = encode_base64($u . ":" . $hashed_password);
	my $value = encode_base64($u . ":" . $p, "");
	return 'Authorization=Basic%20' . uri_escape($value);
}

# 1 - path
sub path_with_token {
	my ($path) = @_;

	if (!defined $url_token) {
		get_url_token();
	}

	return "/" . $url_token . $path;
}

# 1 - path
# 2 - include_referer = true
sub get_page {
	my ($path, $referer) = @_;

	$referer = 1 unless defined $referer;

	my $ua = LWP::UserAgent->new();
	$ua->agent("USER/AGENT/IDENTIFICATION");

	my $uri = "http://" . $host . $path;
	my $request = HTTP::Request->new(GET => $uri);
	$request->header('Cookie' => $auth_cookie);

	if ($referer == 1) {
		my $referer_val = "http://$host" . path_with_token('/userRpm/Index.htm');
		Dbg("Added referer: $referer_val");
		$request->header('Referer' => $referer_val);
	}

	Dbg("Sending req for page $path with referer $referer");

	my $response = $ua->request($request);
	my $content = $response->content();
	Dbg("Response: $content");
	return $content;
}

sub get_url_token {
	if (defined $url_token) {
		return $url_token;
	}

	get_page('/', 0);
	my $resp = get_page('/userRpm/LoginRpm.htm?Save=Save', 0);
	if ($resp =~ /http:\/\/[^\/]+\/([A-Za-z0-9]+)/) {
		$url_token = $1;
		Dbg("URL token is: $url_token");
	}
}

sub get_status_page {
	get_page(path_with_token("/userRpm/StatusRpm.htm"));
}

sub get_wireless_stats_page {
	get_page(path_with_token("/userRpm/WlanStationRpm.htm"));
}

sub get_wireless_stats_page_5g {
	get_page(path_with_token("/userRpm/WlanStationRpm_5g.htm"));
}

# 1 - page
# 2 - name
sub extract_js_array {
	my ($page, $name) = @_;
	my @clients = ();
	if ($page =~ /$name\s+=\s+new\s+Array\(\n(.+?)\)/s) {
		my @array = split(/\n/, $1);
		foreach (@array) {
			Dbg("Array line: $_");
			my @line = split(/,/);
			push(@clients, $line[0]);
		}
	}
	return @clients;
}

sub test {
	my $content = "a\nb\nc\nvar hostList = new Array(\n\"18-1E-B0-66-2A-CB\", 5, 450256, 378696,\n\"10-92-66-7F-C6-62\", 5, 491146, 470950,\n0,0 );\nx\nd\n";
	my @wlan_clients = extract_js_array($content, "hostList");
	Dbg("Clients: " . scalar(@wlan_clients));
}

if ($ARGV[0] and $ARGV[0] eq "config" ) {
	print << 'EOF';
host_name c7

multigraph connected_clients
graph_title Connected clients
graph_info Number of connected clients
graph_category Network
graph yes
graph_vlabel number of clients
clients.label Clients 2.4GHz
clients5.label Clients 5GHz

multigraph wireless_channel
graph_title Wireless channel
graph_category Network
graph_info Wireless channel
graph yes
graph_vlabel channel number
channel.label Channel 2.4GHz
channel5.label Channel 5GHz

multigraph uptime
graph_title Uptime
graph_category System
graph_vlabel days
uptime.label uptime
uptime.draw AREA
EOF
	exit 0;
}

$auth_cookie = build_auth_cookie($user, $pass);

print "multigraph wireless_channel\n";

my $status_page = get_status_page();
my @status = extract_js_array($status_page, 'wlanPara');
my $channel;
if ($status[2] == 15) {
	Dbg("Channel: $status[9]");
	$channel = $status[9];
}
else {
	Dbg("Channel: $status[2]");
	$channel = $status[2];
}
print "channel.value " . $channel . "\n";

my @status_5g = extract_js_array($status_page, 'wlan5GPara');
if ($status_5g[2] == 15) {
	Dbg("Channel: $status_5g[9]");
	$channel = $status_5g[9];
}
else {
	Dbg("Channel: $status_5g[2]");
	$channel = $status_5g[2];
}
print "channel5.value " . $channel . "\n";

print "multigraph connected_clients\n";

my $wireless_stats_page = get_wireless_stats_page();
my @wireless_clients = extract_js_array($wireless_stats_page, 'hostList');
print "clients.value " . (scalar(@wireless_clients) - 1) . "\n";

my $wireless_stats_page_5g = get_wireless_stats_page_5g();
my @wireless_clients_5g = extract_js_array($wireless_stats_page_5g, 'hostList');
print "clients5.value " . (scalar(@wireless_clients_5g) - 1) . "\n";

print "multigraph uptime\n";
@status = extract_js_array($status_page, 'statusPara');
print "uptime.value " . $status[5] / 86400.0 . "\n";
