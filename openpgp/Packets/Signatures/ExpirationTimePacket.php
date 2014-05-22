<?php
namespace OpenPGP\Packets\Signatures;

class ExpirationTimePacket extends \OpenPGP\Packets\Signatures\Subpacket {
  function read() {
    $this->data = $this->read_timestamp();
  }

  function body() {
    return pack('N', $this->data);
  }
}
