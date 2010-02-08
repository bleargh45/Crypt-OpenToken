package Crypt::OpenToken::Cipher::DES3;

use Moose;
use Crypt::DES;

with 'Crypt::OpenToken::Cipher';

sub keysize { 24 }
sub iv_len  { 8 }
sub cipher {
    my ($self, $key, $iv) = @_;
    # XXX: no use of IV ?
    return Crypt::DES->new($key);
}

1;

=head1 NAME

Crypt::OpenToken::Cipher::DES3 - DES3 encryption support for OpenToken

=head1 DESCRIPTION

This library can be used by C<Crypt::OpenToken> to encrypt payloads using
DES3 encryption.

=head1 METHODS

=over

=item keysize()

Returns the key size used for DES3 encryption; 24 bytes.

=item iv_len()

Returns the length of the Initialization Vector needed for DES3 encryption; 8
bytes.

=item cipher($key, $iv)

Returns a C<Crypt::CBC> compatible cipher the implements the DES3 encryption.

=back

=head1 AUTHOR

Graham TerMarsch (cpan@howlingfrog.com)

=head1 COPYRIGHT

=head1 SEE ALSO

L<Crypt::OpenToken::Cipher>

=cut
