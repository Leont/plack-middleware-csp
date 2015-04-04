#! perl 

use Test::More 0.88;
use Plack::Test;

use Plack::Builder;
use HTTP::Request::Common;
 
my $app = sub { return [ 200, [], [ "Hello" ] ] };

my $res = Plack::Test->create($app)->request(GET "/");
is($res->header('Content-Security-Policy'), undef, 'No CSP set');
is($res->content, 'Hello', 'Content is "Hello"');

my $res2 = Plack::Test->create(builder { enable "CSP"; $app })->request(GET "/");
is($res2->header('Content-Security-Policy'), "default-src 'self'", 'CSP set to default');
is($res2->header('X-Content-Security-Policy'), "default-src 'self'", 'X-CSP set to default');

my $res3 = Plack::Test->create(builder { enable "CSP", 'script-src' => 'none'; $app })->request(GET "/");
is($res3->header('Content-Security-Policy'), "script-src 'none'", 'CSP set to script-src => none');

my $res4 = Plack::Test->create(builder { enable "CSP", 'style-src' => [ 'self', 'unsafe-inline' ]; $app })->request(GET "/");
is($res4->header('Content-Security-Policy'), "style-src 'self' 'unsafe-inline'", 'CSP set to style-src => [ self unsafe-inline ]');

my $nonce_app = sub {
	my ($env) = @_;
	return [ 200, [], [ "<script nonce='$env->{'csp.nonce'}'>" ] ];
};
my $res4 = Plack::Test->create(builder { enable "CSP", 'script-src' => [ 'self', 'nonce' ]; $nonce_app })->request(GET "/");
like($res4->header('Content-Security-Policy'), qr/script-src 'self' 'nonce-[A-Za-z0-9+\/=]+'/, 'CSP nonce is set in header');
is($res4->content, "<script nonce='\Q$1\E'>", 'CSP nonce is set in content');

my $header_app = sub { return [ 200, [ 'Content-Security-Policy' => 'sandbox' => [] ], [ "Hello" ] ] };
my $res5 = Plack::Test->create(builder { enable "CSP"; $header_app })->request(GET "/");
is($res5->header('Content-Security-Policy'), 'sandbox', 'CSP header from app overrides our own');

done_testing;
