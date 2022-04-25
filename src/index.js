import qubic from 'qubic-js'
import crypto from "crypto";
const SEED_ALPHABET = 'abcdefghijklmnopqrstuvwxyz';
const PRIVATE_KEY_LENGTH = 32;
export const HASH_LENGTH = 64;
export const PUBLIC_KEY_LENGTH = 32;
export const CHECKSUM_LENGTH = 3;

const QubicJsTools = () => {
    const Aes256Gcm = password => {
        const algorithm = 'aes-256-gcm';
        const HASH_FUNCTION = 'sha256';

        const decrypt = (encrypted) => {
            return new Promise((res, rej) => {
                try {
                    if(!encrypted.hasOwnProperty('ct') || !encrypted.hasOwnProperty('nonce') || !encrypted.hasOwnProperty('authTag')) {
                        return rej('Malformed JSON Message to Decrypt')
                    }

                    const hash = crypto.createHash(HASH_FUNCTION)   //Password is seed, already
                    hash.update(password)                           // 55 random bytes, ok to just hash
                    const derivedKey = Buffer.from(hash.digest('base64'), 'base64')

                    let { ct, nonce, authTag } = encrypted
                    nonce = Buffer.from(nonce, 'base64')
                    const decipher = crypto.createDecipheriv(algorithm, derivedKey, nonce)
                    authTag = Buffer.from(authTag, 'base64')
                    decipher.setAuthTag(authTag)
                    return res(decipher.update(ct, 'base64', 'utf8') + decipher.final('utf8'))
                } catch(error) {
                    return rej(error)
                }
            })
        }
        const encrypt = (data, nonce = null) => {
            return new Promise((res, rej) => {
                try {
                    if(!nonce) {
                        nonce = crypto.randomBytes(12); // 12 byte Nonce. Not great to to random, should not reuse the same key more than 2^32 times
                    }
                    const hash = crypto.createHash(HASH_FUNCTION)   //Password is seed, already
                    hash.update(password)                           // 55 random bytes, ok to just hash
                    const derivedKey = Buffer.from(hash.digest('base64'), 'base64')
                    const cipher = crypto.createCipheriv(algorithm, derivedKey, nonce)
                    const ct = cipher.update(data, 'utf8', 'base64') + cipher.final('base64')
                    const authTag = Buffer.from(cipher.getAuthTag()).toString('base64')
                    return res({ct, nonce: Buffer.from(nonce).toString('base64'), authTag})
                } catch(error) {
                    return rej(error)
                }
            })
        }
        return {
            encrypt,
            decrypt
        }
    }
    const generateSharedSecret = (seed, identity) => {
        return new Promise((res, rej) => {
            try {
                (qubic.crypto).then(async data => {
                    const {schnorrq, K12, kex} = data
                    let pubKey = qubic.shiftedHexToBytes(
                        identity.toLowerCase()
                    )
                        .slice(0, PUBLIC_KEY_LENGTH)
                    const secretKey = await qubic.privateKey(seed, 0, K12)
                    const secretKeyHash = new Uint8Array(HASH_LENGTH);
                    K12(secretKey, secretKeyHash, HASH_LENGTH);
                    const shared = kex.compressedSecretAgreement(secretKeyHash, pubKey)
                    return res(Buffer.from(shared).toString('base64')  )
                })
            }  catch(error) {
                console.error(`Error Generating Shared Secret: ${error}`)
                return rej(error)
            }
        })
    }
    const account = {
        getIdentityFromSeed: (seed, index = 0) => {
            return qubic.identity(seed, index)
        },
        getPublicKeyFromIdentity: identity => {
            const pubKey = qubic.shiftedHexToBytes(
                identity.toLowerCase()
            )
                .slice(0, PUBLIC_KEY_LENGTH)
            return Buffer.from(pubKey).toString('base64')
        },
        genSeed: async () => {
            let seed = ""
            while(seed.length < 55) {
                let random = await crypto.randomBytes(127).toString('hex')
                for(let i = 0; i < random.length; i+= 2) {
                    let c = random[i] + random[i+1]
                    let int = parseInt(`0x${c}`, 16)
                    if(int >= 0 && int < 26) {
                        seed += SEED_ALPHABET[int]
                        if(seed.length >= 55) break
                    }
                }
            }
            const id = await qubic.identity(seed, 0)
            return {seed, id}
        }
    }
    const sig = {
        signData: async (seed, data) => {
            return new Promise((res, rej) => {
                try {
                    (qubic.crypto).then(c => {
                        const { schnorrq, K12 } = c
                        const publicKeyWithChecksum = new Uint8Array(PUBLIC_KEY_LENGTH + CHECKSUM_LENGTH);
                        const sk = qubic.privateKey(seed, 0, K12)
                        let pk = new Uint8Array(PUBLIC_KEY_LENGTH + CHECKSUM_LENGTH);
                        pk.set(schnorrq.generatePublicKey(sk));
                        let signature = schnorrq.sign(sk, pk, data)
                        pk = Buffer.from(pk).toString('base64');
                        signature = Buffer.from(signature).toString('base64');
                        return res({ pk, signature })
                    })
                } catch(error) {
                    console.error(`Error Signing Data: ${error}`)
                    return rej(error)
                }
            })
        },
        verifySignature: (message, sig) => {
            return new Promise((res, rej) => {
                try {
                    if(!sig.hasOwnProperty('pk') || !sig.hasOwnProperty('signature')) {
                        return rej("Malformed Signature Data")
                    }
                    const pk = Buffer.from(sig.pk, 'base64');
                    const signature = Buffer.from(sig.signature, 'base64');
                    (qubic.crypto).then(data => {
                        const {schnorrq, K12} = data
                        const verified = schnorrq.verify(pk, message, signature)
                        return res(verified)
                    })
                } catch(error) {
                    console.error(`Error Verifying Signature: ${error}`)
                    return rej(error)
                }
            })
        }
    }

    const K12 = (data, outputLength) => {
        if (!Number.isInteger(outputLength) || outputLength < 1) {
            throw new Error('Illegal Output Length.');
        }
        return new Promise((res, rej) => {
            try {
                (qubic.crypto).then(crypt => {
                    const output = new Uint8Array(outputLength);
                    crypt.K12(data, output, outputLength, 0)
                    return res(
                        Buffer.from(output).toString('base64')
                    )
                })
            } catch(err) {
                rej(err)
            }
        })
    }
    return {
        account,
        Aes256Gcm,
        generateSharedSecret,
        sig,
        K12
    }
}
window.QubicJsTools = QubicJsTools;