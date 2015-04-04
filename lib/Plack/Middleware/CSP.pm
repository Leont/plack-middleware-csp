package Plack::Middleware::CSP;

use strict;
use warnings;

$Plack::Middleware::CSP::VERSION = '0.001';

use parent 'Plack::Middleware';

use Plack::Util;
use MIME::Base64 'encode_base64';
use List::Util 1.33 'any';

my @directives;
BEGIN {
	@directives = qw/default-src script-src object-src style-src img-src media-src frame-src font-src connect-src form-action sandbox plugin-types reflected-xss report-uri base-uri child-src frame-ancestors referrer/;
}
use Plack::Util::Accessor map { (my $method = $_) =~ s/-/_/; $method } @directives;

my %escaped = map { $_ => qq{'$_'} } qw/self none unsafe-inline unsafe-eval/;

sub new {
	my $class = shift;
	my $self  = $class->SUPER::new(@_);
	$self->{'default-src'} = ['self'] if not any { exists $self->{$_} } @directives;
	$self->{headers} ||= [ 'Content-Security-Policy', 'X-Content-Security-Policy', 'X-WebKit-CSP' ];

	my @nonces;
	for my $directive (@directives) {
		if (my $value = $self->{$directive}) {
			$value = $self->{$directive} = [ $value ] if not ref $value;
			push @nonces, $directive if any { $_ eq 'nonce' } @$value;
		}
	}
	$self->{nonce} = \@nonces;
	$self->{header_value} = $self->generate_value({}) if !@nonces;
	return $self;
}

sub generate_value {
	my ($self, $nonces) = @_;
	my @elements;
	for my $directive (@directives) {
		if (my $value = $self->{$directive}) {
			push @elements, join ' ', $directive, map { _value_escape($_, $nonces, $directive) } @{$value};
		}
	}
	return join '; ', @elements;
}

sub call {
	my ($self, $env) = @_;
	my ($header_value, $nonces) = $self->header_value;
	$env->{'csp.header'} = $header_value;
	$env->{'csp.nonces'} = $nonces if defined $nonces;
	my $orig = $self->app->($env);
	return Plack::Util::response_cb($orig, sub {
		my $res = shift;
		return if Plack::Util::status_with_no_entity_body($res->[0]);
		my $h = Plack::Util::headers($res->[1]);
		return if $h->get('Content-Security-Policy');
		for my $header (@{ $self->{headers} }) {
			$h->push($header, $header_value);
		}
		return;
	});
}

sub header_value {
	my $self = shift;
	if (my @nonced = @{ $self->{nonce} }) {
		my %nonces = map { s/ -src \z //mx; $_ => $self->get_nonce } @nonced;
		return ($self->generate_value(\%nonces), \%nonces);
	}
	else {
		return ($self->{header_value}, undef);
	}
}

sub _value_escape {
	my ($arg, $nonces, $directive) = @_;
	return $escaped{$arg} if $escaped{$arg};
	if ($arg eq 'nonce') {
		my ($nonce_key) = $directive =~ / \A (.*?) (?: -src )? \z /mx;
		return qq{'nonce-$nonces->{$nonce_key}'};
	}
	return $arg;
}

sub get_nonce {
	my $self   = shift;
	my $random = $self->get_random;
	my $ret = encode_base64($random);
	chomp $ret;
	return $ret;
}

sub get_random {
	my $self = shift;
	return $self->{random_source}->() if $self->{random_source};
	return pack 'L', int rand(1 << 31);
}

1;

__END__

=pod

=encoding utf-8

=head1 NAME

Plack::Middleware::CSP - A Plack middleware adding Content Security Policy information

=head1 VERSION

0.001

=head1 DESCRIPTION

This module automatizes adding CSP headers to your responses

=head1 SEE ALSO

=over 4

=item * L<W3C CSP|http://www.w3.org/TR/2014/WD-CSP11-20140211/>

=back

=head1 AUTHOR

Leon Timmermans

=head1 COPYRIGHT AND LICENSE

This software is copyright (c) 2015 by Leon Timmermans.

This is free software; you can redistribute it and/or modify it under
the same terms as the Perl 5 programming language system itself.


1;
