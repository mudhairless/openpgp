<?php
namespace OpenPGP\Packets\Signatures;

/**
 * @see http://tools.ietf.org/html/rfc4880#section-5.2.3.4
 */
class CreationTimePacket extends \OpenPGP\Packets\Signatures\Subpacket {
  function read() {
    $this->data = $this->read_timestamp();
  }

  function body() {
    return pack('N', $this->data);
  }
}
