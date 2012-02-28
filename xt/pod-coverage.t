use Test::Pod::Coverage 1.00;
all_pod_coverage_ok( {
    trustme => [ qr/^CIPHERS$/, qr/^TOKEN_PACK$/ ],
} );
