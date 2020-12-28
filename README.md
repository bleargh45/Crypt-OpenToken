# NAME

Crypt::OpenToken - Perl implementation of Ping Identity's "OpenToken"

# SYNOPSIS

```perl
use Crypt::OpenToken;

$data = {
    foo => 'bar',
    bar => 'baz',
};

# create an OpenToken factory based on a given shared password
$factory = Crypt::OpenToken->new(password => $password);

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
```

# DESCRIPTION

This module provides a Perl implementation of the "OpenToken" standard as
defined by Ping Identity in their IETF Draft.

# METHODS

- Crypt::OpenToken->new(password => $password)

    Instantiates a new OpenToken factory, which can encrypt/decrypt OpenTokens
    using the specified shared `$password`.

- $factory->create($cipher, $data)

    Encrypts the given hash-ref of `$data` using the specified `$cipher` (which
    should be one of the `CIPHER_*` constants).

    Returns back to the caller a Base64 encoded string which represents the
    OpenToken.

    **NOTE:** during the encryption of the OpenToken, a random Initialization
    Vector will be selected; as such it is _not_ possible to encrypt the same
    data more than once and get the same OpenToken back.

- $factory->parse($token)

    Decrypts a Base64 encoded OpenToken, returning a `Crypt::OpenToken::Token`
    object back to the caller.  Throws a fatal exception in the event of an error.

    It is the callers responsibility to then check to see if the token itself is
    valid (see [Crypt::OpenToken::Token](https://metacpan.org/pod/Crypt%3A%3AOpenToken%3A%3AToken) for details).

# CONSTANTS

The following constant values are available for selecting an encrytion cipher
to use:

- Crypt::OpenToken::CIPHER\_NULL

    "Null" encryption (e.g. no encryption whatsoever).  Requires `Crypt::NULL`.

- Crypt::OpenToken::CIPHER\_AES256

    "AES" encryption, 256-bit.  Requires `Crypt::Rijndael`.

- Crypt::OpenToken::CIPHER\_AES128

    "AES" encryption, 128-bit.  Requires `Crypt::Rijndael`.

- Crypt::OpenToken::CIPHER\_DES3

    "TripleDES" encryption, 168-bit.  Requires `Crypt::DES`.

# CAVEATS

- This module does not (yet) support the "obfuscate password" option that is
configurable within PingFederate's OpenToken adapter.

# AUTHOR

Graham TerMarsch (cpan@howlingfrog.com)

Shawn Devlin (shawn.devlin@socialtext.com)

## Contributors

Thanks to those who have provided feedback, comments, and patches:

```perl
Jeremy Stashewsky
Travis Spencer
```

## Sponsors

**BIG** thanks also go out to those who sponsored `Crypt::OpenToken`:

- Socialtext

    Thanks for sponsoring the initial development of `Crypt::OpenToken`, and then
    being willing to release it to the world.

- Ping Identity

    Thanks for your assistance during the initial development, providing feedback
    along the way, and answering our questions as they arose.

# COPYRIGHT & LICENSE

## Crypt::OpenToken

`Crypt::OpenToken` is Copyright (C) 2010, Socialtext, and is released under
the Artistic-2.0 license.

## OpenToken specification

The OpenToken specification is Copyright (C) 2007-2010 Ping Identity
Corporation, and released under the MIT License:

> Permission is hereby granted, free of charge, to any person obtaining a copy
> of this software and associated documentation files (the "Software"), to deal
> in the Software without restriction, including without limitation the rights
> to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
> copies of the Software, and to permit persons to whom the Software is
> furnished to do so, subject to the following conditions:
>
> The above copyright notice and this permission notice shall be included in all
> copies or substantial portions of the Software.
>
> THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
> IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
> FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
> AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
> LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
> OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
> SOFTWARE.

# SEE ALSO

- [http://tools.ietf.org/html/draft-smith-opentoken-02](http://tools.ietf.org/html/draft-smith-opentoken-02)
- [http://www.pingidentity.com/opentoken](http://www.pingidentity.com/opentoken)
