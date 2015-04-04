requires 'List::Util', '1.33';
requires 'MIME::Base64';
requires 'Plack::Middleware';
requires 'Plack::Util';
requires 'Plack::Util::Accessor';
requires 'parent';

on configure => sub {
    requires 'Module::Build::Tiny', '0.039';
    requires 'perl', '5.006';
};

on test => sub {
    requires 'HTTP::Request::Common';
    requires 'Plack::Builder';
    requires 'Plack::Test';
    requires 'Test::More', '0.88';
};
