<?php
//////////////////////////////////////////////////////////////////////////////
// OpenPGP packets

namespace OpenPGP;
/**
 * OpenPGP packet.
 *
 * @see http://tools.ietf.org/html/rfc4880#section-4.1
 * @see http://tools.ietf.org/html/rfc4880#section-4.3
 */
class Packet {
  public $tag, $size, $data;

  static function class_for($tag) {
    return isset(self::$tags[$tag]) && class_exists(
      $class = '\\OpenPGP\\' . self::$tags[$tag] . 'Packet') ? $class : __CLASS__;
  }

  /**
   * Parses an OpenPGP packet.
   *
   * @see http://tools.ietf.org/html/rfc4880#section-4.2
   */
  static function parse(&$input) {
    $packet = NULL;
    if (strlen($input) > 0) {
      $parser = ord($input[0]) & 64 ? 'parse_new_format' : 'parse_old_format';
      list($tag, $head_length, $data_length) = self::$parser($input);
      $input = substr($input, $head_length);
      if ($tag && ($class = self::class_for($tag))) {
        $packet = new $class();
        $packet->tag    = $tag;
        $packet->input  = substr($input, 0, $data_length);
        $packet->length = $data_length;
        $packet->read();
        unset($packet->input);
        unset($packet->length);
      }
      $input = substr($input, $data_length);
    }
    return $packet;
  }

  /**
   * Parses a new-format (RFC 4880) OpenPGP packet.
   *
   * @see http://tools.ietf.org/html/rfc4880#section-4.2.2
   */
  static function parse_new_format($input) {
    $tag = ord($input[0]) & 63;
    $len = ord($input[1]);
    if($len < 192) { // One octet length
      return array($tag, 2, $len);
    }
    if($len > 191 && $len < 224) { // Two octet length
      return array($tag, 3, (($len - 192) << 8) + ord($input[2]) + 192);
    }
    if($len == 255) { // Five octet length
      $unpacked = unpack('N', substr($input, 2, 4));
      return array($tag, 6, reset($unpacked));
    }
    // TODO: Partial body lengths. 1 << ($len & 0x1F)
  }

  /**
   * Parses an old-format (PGP 2.6.x) OpenPGP packet.
   *
   * @see http://tools.ietf.org/html/rfc4880#section-4.2.1
   */
  static function parse_old_format($input) {
    $len = ($tag = ord($input[0])) & 3;
    $tag = ($tag >> 2) & 15;
    switch ($len) {
      case 0: // The packet has a one-octet length. The header is 2 octets long.
        $head_length = 2;
        $data_length = ord($input[1]);
        break;
      case 1: // The packet has a two-octet length. The header is 3 octets long.
        $head_length = 3;
        $data_length = unpack('n', substr($input, 1, 2));
        $data_length = $data_length[1];
        break;
      case 2: // The packet has a four-octet length. The header is 5 octets long.
        $head_length = 5;
        $data_length = unpack('N', substr($input, 1, 4));
        $data_length = $data_length[1];
        break;
      case 3: // The packet is of indeterminate length. The header is 1 octet long.
        $head_length = 1;
        $data_length = strlen($input) - $head_length;
        break;
    }
    return array($tag, $head_length, $data_length);
  }

  function __construct($data=NULL) {
    $this->tag = array_search(substr(substr(get_class($this), 8), 0, -6), self::$tags);
    $this->data = $data;
  }

  function read() {
  }

  function body() {
    return $this->data; // Will normally be overridden by subclasses
  }

  function header_and_body() {
    $body = $this->body(); // Get body first, we will need it's length
    $tag = chr($this->tag | 0xC0); // First two bits are 1 for new packet format
    $size = chr(255).pack('N', strlen($body)); // Use 5-octet lengths
    return array('header' => $tag.$size, 'body' => $body);
  }

  function to_bytes() {
    $data = $this->header_and_body();
    return $data['header'].$data['body'];
  }

  /**
   * @see http://tools.ietf.org/html/rfc4880#section-3.5
   */
  function read_timestamp() {
    return $this->read_unpacked(4, 'N');
  }

  /**
   * @see http://tools.ietf.org/html/rfc4880#section-3.2
   */
  function read_mpi() {
    $length = $this->read_unpacked(2, 'n');  // length in bits
    $length = (int)floor(($length + 7) / 8); // length in bytes
    return $this->read_bytes($length);
  }

  /**
   * @see http://php.net/manual/en/function.unpack.php
   */
  function read_unpacked($count, $format) {
    $unpacked = unpack($format, $this->read_bytes($count));
    return reset($unpacked);
  }

  function read_byte() {
    return ($bytes = $this->read_bytes()) ? $bytes[0] : NULL;
  }

  function read_bytes($count = 1) {
    $bytes = substr($this->input, 0, $count);
    $this->input = substr($this->input, $count);
    return $bytes;
  }

  static $tags = array(
     1 => 'AsymmetricSessionKey',      // Public-Key Encrypted Session Key
     2 => 'Signature',                 // Signature Packet
     3 => 'SymmetricSessionKey',       // Symmetric-Key Encrypted Session Key Packet
     4 => 'OnePassSignature',          // One-Pass Signature Packet
     5 => 'SecretKey',                 // Secret-Key Packet
     6 => 'PublicKey',                 // Public-Key Packet
     7 => 'SecretSubkey',              // Secret-Subkey Packet
     8 => 'CompressedData',            // Compressed Data Packet
     9 => 'EncryptedData',             // Symmetrically Encrypted Data Packet
    10 => 'Marker',                    // Marker Packet
    11 => 'LiteralData',               // Literal Data Packet
    12 => 'Trust',                     // Trust Packet
    13 => 'UserID',                    // User ID Packet
    14 => 'PublicSubkey',              // Public-Subkey Packet
    17 => 'UserAttribute',             // User Attribute Packet
    18 => 'IntegrityProtectedData',    // Sym. Encrypted and Integrity Protected Data Packet
    19 => 'ModificationDetectionCode', // Modification Detection Code Packet
    60 => 'Experimental',              // Private or Experimental Values
    61 => 'Experimental',              // Private or Experimental Values
    62 => 'Experimental',              // Private or Experimental Values
    63 => 'Experimental',              // Private or Experimental Values
  );
}
