<?php
require dirname(__FILE__).'/../vendor/autoload.php';

class FingerprintTest extends PHPUnit_Framework_TestCase {
  public function oneFingerprint($path, $kf) {
    $m = \OpenPGP\Message::parse(file_get_contents(dirname(__FILE__) . '/data/' . $path));
    $this->assertEquals($m[0]->fingerprint(), $kf);
  }

  public function test000001006public_key() {
    $this->oneFingerprint("000001-006.public_key", "421F28FEAAD222F856C8FFD5D4D54EA16F87040E");
  }

  public function test000016006public_key() {
    $this->oneFingerprint("000016-006.public_key", "AF95E4D7BAC521EE9740BED75E9F1523413262DC");
  }

  public function test000027006public_key() {
    $this->oneFingerprint("000027-006.public_key", "1EB20B2F5A5CC3BEAFD6E5CB7732CF988A63EA86");
  }

  public function test000035006public_key() {
    $this->oneFingerprint("000035-006.public_key", "CB7933459F59C70DF1C3FBEEDEDC3ECF689AF56D");
  }
}