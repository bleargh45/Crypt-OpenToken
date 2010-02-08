package Crypt::OpenToken;

use Moose;
use Carp qw(croak);
use MIME::Base64 qw(encode_base64 decode_base64);
use Compress::Zlib;
use Digest::HMAC_SHA1;
use Data::Dumper qw(Dumper);
use Crypt::CBC;
use Crypt::OpenToken::KeyGenerator;
use Crypt::OpenToken::Serializer;
use Crypt::OpenToken::Token;
require bytes;

our $VERSION = '0.01';
our $DEBUG   = 0;

# shared encryption password
has 'password' => (
    is       => 'rw',
    isa      => 'Str',
    required => 1,
);

{
    # List of ciphers supported by OpenTokens (order here *IS* important);
    my @CIPHER_MODULES = qw( null AES256 AES128 DES3 );
    sub CIPHER_NULL   { 0 }
    sub CIPHER_AES256 { 1 }
    sub CIPHER_AES128 { 2 }
    sub CIPHER_DES3   { 3 }
    sub _cipher {
        my ($self, $cipher) = @_;

        my $impl = $CIPHER_MODULES[$cipher];
        unless ($impl) {
            croak "unsupported OTK cipher; '$cipher'";
        }

        my $mod = "Crypt::OpenToken::Cipher::$impl";
        eval "require $mod";
        if ($@) {
            croak "unable to load cipher '$impl'; $@";
        }
        print "selected cipher: $impl\n" if $DEBUG;
        return $mod->new;
    }
}

sub parse {
    my ($self, $token_str) = @_;
    print "parsing token: $token_str\n" if $DEBUG;

    # base64 decode the OTK
    $token_str = $self->_base64_decode($token_str);

    # unpack the OTK token into its component fields
    my $fields = $self->_unpack($token_str);
    print "unpacked fields: " . Dumper($fields) if $DEBUG;

    # get the chosen cipher, and make sure the IV length is valid
    my $cipher = $self->_cipher( $fields->{cipher} );
    my $iv_len = $fields->{iv_len};
    unless ($iv_len == $cipher->iv_len) {
        croak "invalid IV length ($iv_len) for selected cipher ($cipher)";
    }

    # generate a decryption key for this cipher
    my $key = Crypt::OpenToken::KeyGenerator::generate(
        $self->password, $cipher->keysize,
    );
    print "generated key: " . encode_base64($key) if $DEBUG;

    # decrypt the payload
    my $crypto    = $cipher->cipher($key, $fields->{iv});
    my $decrypted = $crypto->decrypt($fields->{payload});
    print "decrypted payload: " . encode_base64($decrypted) if $DEBUG;

    # uncompress the payload
    my $plaintext = Compress::Zlib::uncompress($decrypted);
    print "plaintext:\n$plaintext\n" if $DEBUG;

    # verify the HMAC
    my $hmac = $self->_create_hmac($key, $fields, $plaintext);
    unless ($hmac eq $fields->{hmac}) {
        croak "invalid HMAC";
    }

    # deserialize the plaintext payload
    my %params = Crypt::OpenToken::Serializer::thaw($plaintext);
    print "payload: " . Dumper(\%params) if $DEBUG;
    $fields->{data} = \%params;

    # instantiate the token object
    my $token = Crypt::OpenToken::Token->new($fields);
    return $token;
}

sub create {
    my ($self, $cipher, $data) = @_;

    # get the chosen cipher, and generate a random IV for the encryption
    my $cipher_obj = $self->_cipher($cipher);
    my $iv         = Crypt::CBC->random_bytes($cipher_obj->iv_len);

    # generate an encryption key for this cipher
    my $key = Crypt::OpenToken::KeyGenerator::generate(
        $self->password, $cipher_obj->keysize,
    );
    print "generated key: " . encode_base64($key) if $DEBUG;

    # serialize the data into a payload
    my $plaintext = Crypt::OpenToken::Serializer::freeze(%{$data});
    print "plaintext:\n$plaintext\n" if $DEBUG;

    # compress the payload
    my $compressed = Compress::Zlib::compress($plaintext);
    print "compressed plaintext: " . encode_base64($compressed) if $DEBUG;

    # encrypt the token, w/PKCS5 padding
    my $crypto    = $cipher_obj->cipher($key, $iv);
    my $padded    = $self->_pkcs5_padded($compressed, $crypto->blocksize());
    my $encrypted = $crypto->encrypt($padded);
    print "encrypted payload: " . encode_base64($encrypted) if $DEBUG;

    # gather up all of the fields
    my %fields = (
        version     => 1,
        cipher      => $cipher,
        iv_len      => bytes::length($iv),
        iv          => $iv,
        key_len     => bytes::length($key),
        key         => $key,
        payload_len => bytes::length($encrypted),
        payload     => $encrypted,
    );

    # create an HMAC
    my $hmac = $self->_create_hmac($key, \%fields, $plaintext);
    print "calculated hmac: " . encode_base64($hmac) if $DEBUG;
    $fields{hmac} = $hmac;

    # pack the OTK token together from its component fields
    my $token = $self->_pack(%fields);
    print "binary token: $token\n" if $DEBUG;

    # base64 encode the token
    my $token_str = $self->_base64_encode($token);
    print "token created: $token_str\n" if $DEBUG;
    return $token_str;
}

sub _pkcs5_padded {
    my ($self, $data, $bsize) = @_;
    if ($bsize) {
        my $pad_needed = bytes::length($data) % $bsize;
        $data .= chr($pad_needed) x $pad_needed;
    }
    return $data;
}

sub _create_hmac {
    my ($self, $key, $fields, $plaintext) = @_;

    my $digest = Digest::HMAC_SHA1->new($key);
    $digest->add(chr($fields->{version}));
    $digest->add(chr($fields->{cipher}));
    $digest->add($fields->{iv})  if ($fields->{iv_len} > 0);
    $digest->add($fields->{key}) if ($fields->{key_len} > 0);
    $digest->add($plaintext);

    return $digest->digest;
}

sub _unpack {
    my ($self, $token_str) = @_;
    my ($literal, $version, $cipher, $hmac);
    my ($iv_len, $iv);
    my ($key_len, $key);
    my ($payload_len, $payload);
    my $leftover;

    # have to unpack the token in stages, as it has embedded lengths within it
    # for other items in the structure.
    $literal =     bytes::substr $token_str, 0, 3, '';
    $version = ord bytes::substr $token_str, 0, 1, '';
    $cipher  = ord bytes::substr $token_str, 0, 1, '';
    $hmac    =     bytes::substr $token_str, 0, 20, '';

    unless ($literal eq 'OTK') {
        croak "invalid literal identifier in OTK; '$literal'";
    }
    unless ($version == 1) {
        croak "unsupported OTK version; '$version'";
    }

    $iv_len = ord bytes::substr $token_str, 0, 1, '';
    $iv     =     bytes::substr $token_str, 0, $iv_len, '';

    $key_len = ord bytes::substr $token_str, 0, 1, '';
    $key     =     bytes::substr $token_str, 0, $key_len, '';

    $payload_len = bytes::substr $token_str, 0, 2, '';
    $payload = $token_str;

    return {
        version     => $version,
        cipher      => $cipher,
        hmac        => $hmac,
        iv_len      => $iv_len,
        iv          => $iv,
        key_len     => $key_len,
        key         => $key,
        payload_len => $payload_len,
        payload     => $payload,
    };
}

sub _pack {
    my ($self, %fields) = @_;
    my $token_str
        = 'OTK'
        . chr($fields{version})
        . chr($fields{cipher})
        . bytes::substr($fields{hmac}, 0, 20)
        . chr($fields{iv_len})
        . bytes::substr($fields{iv}, 0, $fields{iv_len})
        . chr($fields{key_len})
        . bytes::substr($fields{key}, 0, $fields{key_len})
        . pack('S', $fields{payload_len})
        . bytes::substr($fields{payload}, 0, $fields{payload_len});
    return $token_str;
}

# Custom Base64 decoding; OTK has some oddities in how they encode things
# using Base64.
sub _base64_decode {
    my ($self, $token_str) = @_;

    # fixup: convert trailing "*"s into "="s (OTK specific encoding)
    $token_str =~ s/(\*+)$/'=' x length($1)/e;

    # fixup: convert "_" to "/" (PingId PHP bindings encode this way)
    $token_str =~ s{_}{/}g;

    # fixup: convert "-" to "+" (PingId PHP bindings encode this way)
    $token_str =~ s{-}{+}g;

    # Base64 decode it, and we're done.
    my $decoded = decode_base64($token_str);
    return $decoded;
}

# Custom Base64 encoding; OTK has some oddities in how they encode things
# using Base64.
sub _base64_encode {
    my ($self, $token_str) = @_;

    # Base64 encode the token string
    my $encoded = encode_base64($token_str, '');

    # fixup: convert "+" to "-" (PingId PHP bindings encode this way)
    $encoded =~ s{\+}{-}g;

    # fixup: convert "/" to "_" (PingId PHP bindings encode this way)
    $encoded =~ s{/}{_}g;

    # fixup: convert trailing "="s to "*"s (OTK specific encoding)
    $encoded =~ s/(\=+)$/'*' x length($1)/e;

    return $encoded;
}

no Moose;

1;

=head1 NAME

Crypt::OpenToken - Perl implementation of Ping Identity's "OpenToken"

=head1 SYNOPSIS

  use Crypt::OpenToken;

  $data = {
      foo => 'bar',
      bar => 'baz',
  };

  # create an OpenToken factory based on a given shared password
  $factory = Crypt::OpenToken->new($password);

  # encrypt a hash-ref of data into an OpenToken.
  $token_str = $factory->create(
      Crypt::OpenToken::CIPHER_AES128,
      $data,
  );

  # decrypt an OpenToken, check if its valid, and get data back out
  $token = $factory->parse($token_str);
  if ($token->is_valid) {
      $data = $token->data();
  }

=head1 DESCRIPTION

This module implements a Perl implementation of the "OpenToken" standard as
defined by Ping Identity in their IETF Draft.

=head1 METHODS

=over

=item Crypt::OpenToken->new($password)

Instantiates a new OpenToken factory, which can encrypt/decrypt OpenTokens
using the specified shared C<$password>.

=item $factory->create($cipher, $data)

Encrypts the given hash-ref of C<$data> using the specified C<$cipher> (which
should be one of the C<CIPHER_*> constants).

Returns back to the caller a Base64 encoded string which represents the
OpenToken.

B<NOTE:> during the encryption of the OpenToken, a random Initialization
Vector will be selected; as such it is I<not> possible to encrypt the same
data more than once and get the same OpenToken back.

=item $factory->parse($token)

Decrypts a Base64 encoded OpenToken, returning a C<Crypt::OpenToken::Token>
object back to the caller.  Throws a fatal exception in the event of an error.

It is the callers responsibility to then check to see if the token itself is
valid (see L<Crypt::OpenToken::Token> for details).

=back

=head1 CONSTANTS

The following constant values are available for selecting an encrytion cipher
to use:

=over

=item Crypt::OpenToken::CIPHER_NULL

"Null" encryption (e.g. no encryption whatsoever).  Requires C<Crypt::NULL>.

=item Crypt::OpenToken::CIPHER_AES256

"AES" encryption, 256-bit.  Requires C<Crypt::Rijndael>.

=item Crypt::OpenToken::CIPHER_AES128

"AES" encryption, 128-bit.  Requires C<Crypt::Rijndael>.

=item Crypt::OpenToken::CIPHER_DES3

"TripleDES" encryption, 168-bit.  Requires C<Crypt::DES>.

=back

=head1 AUTHOR

Graham TerMarsch (cpan@howlingfrog.com)

=head1 COPYRIGHT

=head1 SEE ALSO

L<http://www.pingidentity.com/>
L<http://tools.ietf.org/html/draft-smith-opentoken-02>

=cut
