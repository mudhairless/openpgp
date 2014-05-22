<?php
namespace OpenPGP\Packets\Signatures;

class ReasonForRevocationPacket extends \OpenPGP\Packets\Signatures\Subpacket {
  public $code;

  function read() {
    $this->code = ord($this->read_byte());
    $this->data = $this->input;
  }

  function body() {
    return chr($this->code) . $this->data;
  }
}
