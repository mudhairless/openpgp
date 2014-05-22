<?php
namespace OpenPGP\Packets\Signatures;

class SignersUserIDPacket extends \OpenPGP\Packets\Signatures\Subpacket {
  function read() {
    $this->data = $this->input;
  }

  function body() {
    return $this->data;
  }
}
