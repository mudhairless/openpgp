<?php
namespace OpenPGP\Packets\Signatures;

class PrimaryUserIDPacket extends \OpenPGP\Packets\Signatures\Subpacket {
  function read() {
    $this->data = (ord($this->input) != 0);
  }

  function body() {
    return chr($this->data ? 1 : 0);
  }

}
