// pgp.go
package main

import (
    "io"

    "golang.org/x/crypto/openpgp"
    "golang.org/x/crypto/openpgp/armor"
    "golang.org/x/crypto/openpgp/packet"
)

// EncryptHybridStream encrypts a stream using hybrid encryption:
// - Encrypts the session key (from KMS) to each recipient's public key(s).
// - Encrypts the data symmetrically with that session key.
// - Outputs a standard armored OpenPGP message.
func EncryptHybridStream(w io.Writer, recipients openpgp.EntityList, plaintext io.Reader, sessionKey []byte) error {
    // Step 1: Create armored PGP message
    aw, err := armor.Encode(w, "PGP MESSAGE", nil)
    if err != nil {
        return err
    }
    defer aw.Close()

    config := &packet.Config{}

    // Step 2: Serialize symmetrically encrypted integrity packet header.
    // This returns a WriteCloser for the encrypted data.
    encContents, err := packet.SerializeSymmetricallyEncrypted(
        aw,
        packet.CipherAES256, // Explicit cipher function
        sessionKey,
        config,
    )
    if err != nil {
        return err
    }
    defer encContents.Close()

    // Step 3: Serialize encrypted session key packets for each recipient.
    // This allows recipients to recover the session key with their private key.
    for _, entity := range recipients {
        // Prefer encryption subkeys (standard practice).
        added := false
        for _, subkey := range entity.Subkeys {
            if subkey.PublicKey.PubKeyAlgo.CanEncrypt() {
                err := packet.SerializeEncryptedKey(
                    encContents,
                    subkey.PublicKey, // The public key to encrypt TO
                    packet.CipherAES256, // Cipher used for the symmetric encryption
                    sessionKey, // The session key to encrypt
                    config,
                )
                if err != nil {
                    return err
                }
                added = true
                break
            }
        }
        // Fallback to primary key if no suitable subkey.
        if !added && entity.PrimaryKey.PubKeyAlgo.CanEncrypt() {
            err := packet.SerializeEncryptedKey(
                encContents,
                entity.PrimaryKey, // The public key to encrypt TO
                packet.CipherAES256, // Cipher used for the symmetric encryption
                sessionKey, // The session key to encrypt
                config,
            )
            if err != nil {
                return err
            }
        }
    }

    // Step 4: Stream the actual plaintext data into the symmetric encrypter.
    // This gets OCFB-encrypted inline.
    _, err = io.Copy(encContents, plaintext)
    return err
}
