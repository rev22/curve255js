/**
 * @fileOverview
 * Curve25519 compliance tests with test vectors taken from NaCl tests.
 */

/*
 * Created: 21 May 2014 Guy K. Kloss <gk@mega.co.nz>
 *
 * (c) 2014 by Mega Limited, Wellsford, New Zealand
 *     http://mega.co.nz/
 *     MIT License.
 *
 * You should have received a copy of the license along with this
 * program.
 */



// ---8<------------------------------------------------------------------

// This is for stand-alone testing via 'node compliance_test.js',
// remove this section for using the test with Karma

var fs = require('fs');
eval(fs.readFileSync("../curve255.js").toString())

var chai = require('chai');
var describe = function (s, x) { console.log(s); x(); };
var it = function (s, x) { console.log(s); x(); };
  
var _td = {};

// NaCl test vectors.
// Conveniently poached from
// https://github.com/cryptosphere/rbnacl/blob/master/lib/rbnacl/test_vectors.rb
_td.ALICE_PRIV = '77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a';
_td.ALICE_PUB  = '8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a';
_td.BOB_PRIV   = '5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb';
_td.BOB_PUB    = 'de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f';
_td.SECRET_KEY = '4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742';

_td.testVectors = [];

// ---8<------------------------------------------------------------------


(function() {
    "use strict";

    function hex2ibh(x) {
	// Pad with '0' at the front
	x = new Array(64 + 1 - x.length).join("0") + x;
	// Invert bytes
	return x.split(/(..)/).reverse().join("");
    }
    
    function ibh2hex(x) {
	// assert(length(x) == 64);
	// Invert bytes
	return x.split(/(..)/).reverse().join("");
    }
    
    function encode_vector(k) { return hex2ibh(c255lhexencode(k)); }
    function decode_vector(v) { return c255lhexdecode(ibh2hex(v)); }
    
    var assert = chai.assert;

    describe("Curve25519 compliance tests)", function() {
        describe('NaCl test vectors', function() {
            it('Alice computes her pub key', function() {
                var result = curve25519(decode_vector(_td.ALICE_PRIV));
                assert.strictEqual(encode_vector(result), _td.ALICE_PUB);
            });
            
            it('Bob computes his pub key', function() {
                var result = curve25519(decode_vector(_td.BOB_PRIV));
                assert.strictEqual(encode_vector(result), _td.BOB_PUB);
            });
            
            it('Alice computes secret key', function() {
                var result = curve25519(decode_vector(_td.ALICE_PRIV),
                                        decode_vector(_td.BOB_PUB));
                assert.strictEqual(encode_vector(result), _td.SECRET_KEY);
            });
            
            it('Bob computes secret key', function() {
                var result = curve25519(decode_vector(_td.BOB_PRIV),
                                        decode_vector(_td.ALICE_PUB));
                assert.strictEqual(encode_vector(result), _td.SECRET_KEY);
            });
        });
    });
})();
