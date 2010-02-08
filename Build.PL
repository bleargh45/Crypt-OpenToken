use strict;
use warnings;
use Module::Build;

Module::Build->new(
    module_name => 'Crypt::OpenToken',
    dist_author => 'Graham TerMarsch (cpan@howlingfrog.com)',
    license     => 'artistic',
    requires    => {
        'MIME::Base64'      => 0,
        'Digest::HMAC_SHA1' => 0,
        'Crypt::Rijndael'   => 0,
    },
    recommends => {
        'Crypt::DES'  => 0,
        'Crypt::NULL' => 0,
    },
    build_requires => {
        'Test::More'        => 0,
        'Test::Differences' => 0,
        'Test::Exception'   => 0,
    },
)->create_build_script();
