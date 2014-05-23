<?php
namespace OpenPGP\Packets;
/**
 * OpenPGP Secret-Key packet (tag 5).
 *
 * @see http://tools.ietf.org/html/rfc4880#section-5.5.1.3
 * @see http://tools.ietf.org/html/rfc4880#section-5.5.3
 * @see http://tools.ietf.org/html/rfc4880#section-11.2
 * @see http://tools.ietf.org/html/rfc4880#section-12
 */
class SecretKeyPacket extends \OpenPGP\Packets\PublicKeyPacket {
  public $s2k_useage, $s2k, $symmetric_algorithm, $private_hash, $encrypted_data;
  function read() {
    parent::read(); // All the fields from PublicKey
    $this->s2k_useage = ord($this->read_byte());
    if($this->s2k_useage == 255 || $this->s2k_useage == 254) {
      $this->symmetric_algorithm = ord($this->read_byte());
      $this->s2k = \OpenPGP\S2K::parse($this->input);
    } else if($this->s2k_useage > 0) {
      $this->symmetric_algorithm = $this->s2k_useage;
    }
    if($this->s2k_useage > 0) {
      $this->encrypted_data = $this->input; // Rest of input is MPIs and checksum (encrypted)
    } else {
      $this->key_from_input();
      $this->private_hash = $this->read_bytes(2); // TODO: Validate checksum?
    }
  }

  static $secret_key_fields = array(
     1 => array('d', 'p', 'q', 'u'), // RSA
     2 => array('d', 'p', 'q', 'u'), // RSA-E
     3 => array('d', 'p', 'q', 'u'), // RSA-S
    16 => array('x'),                // ELG-E
    17 => array('x'),                // DSA
  );

  function key_from_input() {
    foreach(self::$secret_key_fields[$this->algorithm] as $field) {
      $this->key[$field] = $this->read_mpi();
    }
  }

  function body() {
    $bytes = parent::body() . chr($this->s2k_useage);
    $secret_material = NULL;
    if($this->s2k_useage == 255 || $this->s2k_useage == 254) {
      $bytes .= chr($this->symmetric_algorithm);
      $bytes .= $this->s2k->to_bytes();
    }
    if($this->s2k_useage > 0) {
      $bytes .= $this->encrypted_data;
    } else {
      $secret_material = '';
      foreach(self::$secret_key_fields[$this->algorithm] as $f) {
        $f = $this->key[$f];
        $secret_material .= pack('n', \OpenPGP\Util::bitlength($f));
        $secret_material .= $f;
      }
      $bytes .= $secret_material;

      // 2-octet checksum
      $chk = 0;
      for($i = 0; $i < strlen($secret_material); $i++) {
        $chk = ($chk + ord($secret_material[$i])) % 65536;
      }
      $bytes .= pack('n', $chk);
    }
    return $bytes;
  }
}
