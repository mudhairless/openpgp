<?php
namespace OpenPGP\Packets\Signatures;

class PreferredKeyServerPacket extends \OpenPGP\Packets\Signatures\Subpacket {
  function read() {
    $this->data = $this->input;
  }

  function body() {
    return $this->data;
  }
}
