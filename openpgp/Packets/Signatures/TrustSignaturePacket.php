<?php
namespace OpenPGP\Packets\Signatures;

class TrustSignaturePacket extends \OpenPGP\Packets\Signatures\Subpacket {
  function read() {
    $this->depth = ord($this->input{0});
    $this->trust = ord($this->input{1});
  }

  function body() {
    return chr($this->depth) . chr($this->trust);
  }
}
