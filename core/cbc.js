/** @fileOverview CBC mode implementation
 *
 * @author Marco Schulte
 */

/** @namespace
 * Dangerous: CBC mode with PKCS#5 padding.
 *
 */
  sjcl.mode.cbc = {
    /** The name of the mode.
     * @constant
     */
    name: "cbc",
    
    /** Encrypt in CBC mode with PKCS#5 padding.
     * @param {Object} prp The block cipher.  It must have a block size of 16 bytes.
     * @param {bitArray} plaintext The plaintext data.
     * @param {bitArray} iv The initialization value.
     * @param {bitArray} [adata=[]] The authenticated data.  Must be empty.
     * @return The encrypted data, an array of bytes.
     * @throws {sjcl.exception.invalid} if the IV isn't exactly 128 bits, or if any adata is specified.
     */
    encrypt: function(prp, plaintext, iv, adata) {
	  if (adata && adata.length) {
	    throw new sjcl.exception.invalid("cbc can't authenticate data");
	  }
	  
	  var i, w = sjcl.bitArray, xor = w._xor4, wi, bo, wiMinusOne, output = [];
          
	  wiMinusOne = iv;
      for (i=0; i+4 <= plaintext.length; i+=4) {
        wi = plaintext.slice(i,i+4);
        bo = prp.encrypt(xor(wiMinusOne, wi));
        output = output.concat(bo);
        wiMinusOne = bo;
      }
	  
	  return output;
    },
    
    /** Decrypt in CBC mode.
     * @param {Object} prp The block cipher.  It must have a block size of 16 bytes.
     * @param {bitArray} ciphertext The ciphertext data.
     * @param {bitArray} iv The initialization value.
     * @param {bitArray} [adata=[]] The authenticated data. Must be empty.
     * @return The decrypted data, an array of bytes.
     * @throws {sjcl.exception.invalid} if the IV isn't exactly 128 bits, or if any adata is specified.
     * @throws {sjcl.exception.corrupt} if if the message is corrupt.
     */
    decrypt: function(prp, ciphertext, iv, adata) {
      if (adata && adata.length) {
        throw new sjcl.exception.invalid("cbc can't authenticate data");
      }
      if (sjcl.bitArray.bitLength(iv) !== 128) {
        throw new sjcl.exception.invalid("cbc iv must be 128 bits");
      }
      if ((sjcl.bitArray.bitLength(ciphertext) & 127) || !ciphertext.length) {
		throw new sjcl.exception.corrupt("cbc ciphertext must be a positive multiple of the block size");
      }
      var i, w = sjcl.bitArray, xor = w._xor4, wi, bo, wiMinusOne, output = [];
          
	  wiMinusOne = iv; 
      for (i=0; i+4 <= ciphertext.length; i+=4) {
        wi = ciphertext.slice(i,i+4);
        bo = xor(wiMinusOne, prp.decrypt(wi));
        output = output.concat(bo);
        wiMinusOne = wi;
      }

      return output;
    }
  };
