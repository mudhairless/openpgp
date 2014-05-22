<?php
namespace OpenPGP\Packets\Signatures;

class TargetPacket extends \OpenPGP\Packets\Signatures\Subpacket {
  public $key_algorithm, $hash_algorithm;

  function read() {
    $this->key_algorithm = ord($this->read_byte());
    $this->hash_algorithm = ord($this->read_byte());
    $this->data = $this->input;
  }

  function body() {
    return chr($this->key_algorithm) . chr($this->hash_algorithm) . $this->data;
  }

}
