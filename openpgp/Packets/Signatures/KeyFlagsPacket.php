<?php
namespace OpenPGP\Packets\Signatures;
class KeyFlagsPacket extends \OpenPGP\Packets\Signatures\Subpacket {
  function __construct($flags=array()) {
    parent::__construct();
    $this->flags = $flags;
  }

  function read() {
    $this->flags = array();
    while($this->input) {
      $this->flags[] = ord($this->read_byte());
    }
  }

  function body() {
    $bytes = '';
    foreach($this->flags as $f) {
      $bytes .= chr($f);
    }
    return $bytes;
  }
}
