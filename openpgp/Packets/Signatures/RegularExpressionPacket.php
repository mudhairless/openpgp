<?php
namespace OpenPGP\Packets\Signatures;

class RegularExpressionPacket extends \OpenPGP\Packets\Signatures\Subpacket {
  function read() {
    $this->data = substr($this->input, 0, -1);
  }

  function body() {
    return $this->data . chr(0);
  }
}
