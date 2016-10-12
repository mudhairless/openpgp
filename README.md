# !! WARNING! THIS CODE IS NOT MAINTAINED AND IS KNOWN TO HAVE ISSUES. !!

I am leaving the code available so that someone who had the inclination
can fork and fix it. In my limited testing encryption works but I cannot
get the reference tools to verify generated signatures and vice versa.

##Implementation of OpenPGP for PHP

Based on the work done at: https://github.com/bendiken/openpgp-php
The only changes from this project were to update to latest PSR standards.

### About OpenPGP

OpenPGP is the most widely-used e-mail encryption standard in the world. It
is defined by the OpenPGP Working Group of the Internet Engineering Task
Force (IETF) Proposed Standard RFC 4880. The OpenPGP standard was originally
derived from PGP (Pretty Good Privacy), first created by Phil Zimmermann in
1991.

* <http://tools.ietf.org/html/rfc4880>
* <http://www.openpgp.org/>

Features
--------

* Encodes and decodes ASCII-armored OpenPGP messages.
* Parses OpenPGP messages into their constituent packets.
  * Supports both old-format (PGP 2.6.x) and new-format (RFC 4880) packets.
* Helper class for verifying and signing messages using Crypt_RSA from <http://phpseclib.sourceforge.net>
