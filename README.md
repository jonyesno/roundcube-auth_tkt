## Overview

auth_tkt is a Roundcube webmail plugin that sets and clears cookies for
the Apache mod_auth_tkt module.

This allows Apache authenticate users to other systems by merit of their
Roundcube login in a simple SSO manner.

 It also redirects to the 'back' URL that mod_auth_tkt provides, if present.

## References

See https://github.com/gavincarr/mod_auth_tkt for more about mod_auth_tkt.

This code includes the hash construction function from PHP contributions to
that project.

## License

Released under [ASL](http://www.opensource.org/licenses/Apache-2.0). See
LICENSE for details.

## Author

Jon Stuart, jon@zomo.co.uk, [Zomo Technology Ltd](http://www.zomo.co.uk), 2014.
