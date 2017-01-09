var crypto = require('crypto');

// test data
// var keySeed = new Buffer("5D5068BEC9B384FF6044867159F16D6B755544FCD5116989B1ACC4278E88", 'hex');
// var keyId = 'D1C1B1A1B2A2B3A3A4B4A5B5C5D5E5F5';
// result=0x2539fa84b987416009a7fbba11b239ab

/**
 *
 * @param keySeed Buffer
 * @param keyId String
 */
module.exports = function(keySeed, keyId) {
    const DRM_AES_KEYSIZE_128 = 16;
    var contentKey = new Buffer(DRM_AES_KEYSIZE_128);

    //
    // Truncate the key seed to 30 bytes, key seed must be at least 30 bytes long.
    //
    var truncatedKeySeed = new Buffer(30);
    keySeed.copy(truncatedKeySeed, 0, 0, truncatedKeySeed.Length);

    //
    // Get the keyId as a byte array
    //
    var keyIdAsBytes = new Buffer(keyId, 'hex');

    var sha256_a = crypto.createHash('sha256');
    sha256_a.update(truncatedKeySeed);
    sha256_a.update(keyIdAsBytes);
    var sha_a = sha256_a.digest();

    var sha256_b = crypto.createHash('sha256');
    sha256_b.update(truncatedKeySeed);
    sha256_b.update(keyIdAsBytes);
    sha256_b.update(truncatedKeySeed);
    var sha_b = sha256_b.digest();

    var sha256_c = crypto.createHash('sha256');
    sha256_c.update(truncatedKeySeed);
    sha256_c.update(keyIdAsBytes);
    sha256_c.update(truncatedKeySeed);
    sha256_c.update(keyIdAsBytes);
    var sha_c = sha256_c.digest();

    for (var i = 0; i < DRM_AES_KEYSIZE_128; i++) {
        contentKey[i] = sha_a[i] ^ sha_a[i + DRM_AES_KEYSIZE_128] ^
            sha_b[i] ^ sha_b[i + DRM_AES_KEYSIZE_128] ^
            sha_c[i] ^ sha_c[i + DRM_AES_KEYSIZE_128];
    }

    return contentKey;
};