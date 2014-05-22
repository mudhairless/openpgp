<?php
namespace OpenPGP\Packets\Signatures;

class Subpacket extends \OpenPGP\Packet {
  function __construct($data=NULL) {
    parent::__construct($data);
    $this->tag = array_search(substr(substr(get_class($this), 8+16), 0, -6), \OpenPGP\Packets\SignaturePacket::$subpacket_types);
  }

  function header_and_body() {
    $body = $this->body(); // Get body first, we will need it's length
    $size = chr(255).pack('N', strlen($body)+1); // Use 5-octet lengths + 1 for tag as first packet body octet
    $tag = chr($this->tag);
    return array('header' => $size.$tag, 'body' => $body);
  }

  /* Defaults for unsupported packets */
  function read() {
    $this->data = $this->input;
  }

  function body() {
    return $this->data;
  }
}
