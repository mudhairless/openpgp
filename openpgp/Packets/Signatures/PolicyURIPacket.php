<?php
namespace OpenPGP\Packets\Signatures;

class PolicyURIPacket extends \OpenPGP\Packets\Signatures\Subpacket {
  function read() {
    $this->data = $this->input;
  }

  function body() {
    return $this->data;
  }
}
