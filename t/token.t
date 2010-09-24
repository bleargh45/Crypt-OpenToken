#!/usr/bin/perl

use strict;
use warnings;
use POSIX qw(strftime);
use Test::More tests => 7;
use Crypt::OpenToken::Token;

###############################################################################
# TEST: instantiation
instantiation: {
    my $token = Crypt::OpenToken::Token->new(version => 1);
    isa_ok $token, 'Crypt::OpenToken::Token';
}

###############################################################################
# TEST: invalid token; before "not-before"
invalid_not_before: {
    my $tomorrow = DateTime->now()->add(days => 1);
    my $date_str = _make_iso8601_date($tomorrow->epoch);

    my $token = Crypt::OpenToken::Token->new( {
        data => { 'not-before' => $date_str },
    } );
    isa_ok $token, 'Crypt::OpenToken::Token';
    ok !$token->is_valid, '... which is invalid; not-before';
}

###############################################################################
# TEST: invalid token; after "not-on-or-after"
invalid_not_on_or_after: {
    my $yesterday = DateTime->now()->add(days => -1);
    my $date_str  = _make_iso8601_date($yesterday->epoch);

    my $token = Crypt::OpenToken::Token->new( {
        data => { 'not-on-or-after' => $date_str },
    } );
    isa_ok $token, 'Crypt::OpenToken::Token';
    ok !$token->is_valid, '... which is invalid; not-on-or-after';
}

###############################################################################
# TEST: valid token
valid: {
    my $yesterday = DateTime->now()->add(days => -1);
    my $tomorrow  = DateTime->now()->add(days => 1);
    my $token = Crypt::OpenToken::Token->new( {
        data => {
            'not-before'      => _make_iso8601_date($yesterday->epoch),
            'not-on-or-after' => _make_iso8601_date($tomorrow->epoch),
        },
    } );
    isa_ok $token, 'Crypt::OpenToken::Token';
    ok $token->is_valid, '... which is valid';
}

sub _make_iso8601_date {
    my $time_t = shift;
    return strftime('%Y-%m-%dT%H:%M:%S%Z', gmtime($time_t));
}