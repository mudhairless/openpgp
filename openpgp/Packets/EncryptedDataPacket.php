<?php
namespace OpenPGP\Packets;
/**
 * OpenPGP Symmetrically Encrypted Data packet (tag 9).
 *
 * @see http://tools.ietf.org/html/rfc4880#section-5.7
 */
class EncryptedDataPacket extends \OpenPGP\Packet {
  function read() {
    $this->data = $this->input;
  }

  function body() {
    return $this->data;
  }
}
