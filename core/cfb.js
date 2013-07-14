/** @fileOverview CFB implementation
 *
 * @author Marco Schulte
 */

sjcl.mode.cfb = {
  /** The name of the mode.
   * @constant
   */
  name: "cfb",
  
  /** Encrypt in OCB mode, version 2.0.
   * @param {Object} prp The block cipher.  It must have a block size of 16 bytes.
   * @param {bitArray} plaintext The plaintext data.
   * @param {bitArray} iv The initialization value.
   * @param {bitArray} [adata=[]] The authenticated data. Must be empty.
   * @return The encrypted data, an array of bytes.
   * @throws {sjcl.exception.invalid} if the IV isn't exactly 128 bits.
   */
  encrypt: function(prp, plaintext, iv, adata) {
  	return decrypt(prp, plaintext, iv, adata);
  },
  
  /** Decrypt in OCB mode.
   * @param {Object} prp The block cipher.  It must have a block size of 16 bytes.
   * @param {bitArray} ciphertext The ciphertext data.
   * @param {bitArray} iv The initialization value.
   * @param {bitArray} [adata=[]] The authenticated data. Must be empty.
   * @return The decrypted data, an array of bytes.
   * @throws {sjcl.exception.invalid} if the IV isn't exactly 128 bits.
   */
  decrypt: function(prp, ciphertext, iv, adata) {
    if (sjcl.bitArray.bitLength(iv) !== 128) {
      throw new sjcl.exception.invalid("cfb iv must be 128 bits");
    }
    if (adata && adata.length) {
    	throw new sjcl.exception.invalid("cfb can't authenticate data");
    }
    
    var i, w = sjcl.bitArray, xor = w._xor4, wi, wiMinusOne, output = [];
    
    wiMinusOne = iv;
    for (i=0; i+4 <= ciphertext.length; i+=4) {
      wi = ciphertext.slice(i,i+4);
      output = output.concat(xor(prp.encrypt(wiMinusOne), ciphertext.slice(i,i+4)));
      wiMinusOne = wi;
    }
    
    return output;
  }
  
};
