requires 'perl', '>= 5.012';
requires 'MIME::Base64';
requires 'Digest::HMAC_SHA1';
requires 'Digest::SHA1';
requires 'Crypt::Rijndael';
requires 'Moose';
requires 'DateTime';
requires 'Date::Parse';
requires 'Compress::Zlib';
requires 'namespace::autoclean';

recommends 'Crypt::CBC';
recommends 'Crypt::DES_EDE3';
recommends 'Crypt::NULL';

test_requires 'Test2::Suite', '>= 0.000118';
