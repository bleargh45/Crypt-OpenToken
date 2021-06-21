#!/usr/bin/perl

use strict;
use warnings;
use if $ENV{AUTOMATED_TESTING}, 'Test::DiagINC'; use MIME::Base64;
use Test2::V0;
use Test2::Require::Module 'Crypt::Rijndael';

use Crypt::OpenToken;

###############################################################################
# TEST DATA
my @test_data = (
    {   # generated w/PingFederate
        password_base64 => 'ZGV2bnVsbA==',
        token => 'T1RLAQKCHZGe_Q6BcMbD-ZdYnYC6XsCu2hA82R-1uYYhvT4K53jKmg3zAACgZTplOrvU030N65GwroXejpAiWswzAFyEIJyLg5HpQoJAdUeAnwZpzBRcPiEvy45TjLJrLzoxf2WPQ01oz6YRBIQT2D2fi4e10Dx5-Gw2-Q4t6jSmX2CaJDmTrlsw4eamUSbq3xNe23JEszEnFoOXDx1qvOUQS79YLOZFr1elCTL6qn88YNbST4EwFaHb_8oTFCqrbD47zQpAiJ3stEQFkw**',
        data  => {
            'subject'         => 'devnull1@socialtext.com',
            'not-on-or-after' => '2010-02-12T00:15:13Z',
            'not-before'      => '2010-02-12T00:10:13Z',
            'authnContext'    => 'urn:oasis:names:tc:SAML:2.0:ac:classes:Password',
            'renew-until'     => '2010-02-12T12:10:13Z'
        },
    },
    {   # generated w/PingId PHP Integration Kit
        password_base64 => 'YTY2QzlNdk04ZVk0cUpLeUNYS1crMTlQV0RldWMzdGg=',
        token => 'T1RLAQLYzm2R0wpOyyqdYp2RQ-t_Im7KLBA2RwUN-GrKzUY36XXJqPHYAAAg1Gg6bi9SwAZTWxp9SfUSSt7ypVAVqbQwS6Flw2cqhCI*',
        data  => {
            foo => 'bar',
            bar => 'baz',
        },
    },
);

###############################################################################
# Decryption; can we parse an OpenToken generated by another implementation?
decryption: {
    foreach my $suite (@test_data) {
        my $token    = $suite->{token};
        my $data     = $suite->{data};
        my $password = decode_base64($suite->{password_base64});

        my $factory   = Crypt::OpenToken->new(password => $password);
        my $decrypted = $factory->parse($token);
        is $decrypted->data(), $data, 'AES-128; decrypt externally generated data';
    }
}

###############################################################################
# Round-trip; if we encrypt/decrypt the data, do we get the data back out?
round_trip: {
    foreach my $suite (@test_data) {
        my $token    = $suite->{token};
        my $data     = $suite->{data};
        my $password = decode_base64($suite->{password_base64});

        my $factory   = Crypt::OpenToken->new(password => $password);
        my $encrypted = $factory->create(Crypt::OpenToken::CIPHER_AES128, $data);
        my $decrypted = $factory->parse($encrypted);
        is $decrypted->data(), $data, 'AES-128; encryption/decryption round-trip';
    }
}

###############################################################################
done_testing();
