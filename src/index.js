import {createIdentity, privateKey, crypto as crypt} from 'qubic-js'
import crypto from "crypto";
const pbkdf2 = require('pbkdf2')
const SEED_ALPHABET = 'abcdefghijklmnopqrstuvwxyz';
const PRIVATE_KEY_LENGTH = 32;
export const PUBLIC_KEY_LENGTH = 32;
export const CHECKSUM_LENGTH = 3;

export const QubicJsTools = () => {
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
                        nonce = crypto.randomBytes(12);   //12 byte Nonce. Not great to to random,
                        // should not reuse the same key more
                        // than 2^32 times
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
    const signData = async (seed, data) => {
        const {schnorrq, K12} = (await crypt)
        const publicKeyWithChecksum = new Uint8Array(PUBLIC_KEY_LENGTH + CHECKSUM_LENGTH);
        const sk = privateKey(seed, 0, K12)
        let pk = new Uint8Array(PUBLIC_KEY_LENGTH + CHECKSUM_LENGTH);
        pk.set(schnorrq.generatePublicKey(sk));
        let signature = schnorrq.sign(sk, pk, data)
        pk = Buffer.from(pk).toString('base64');
        signature = Buffer.from(signature).toString('base64');
        return {pk, signature}
    }
    const verifySignature = (message, sig) => {
        return new Promise((res, rej) => {
            if(!sig.hasOwnProperty('pk') || !sig.hasOwnProperty('signature')) {
                return rej("Malformed Signature Data")
            }
            const pk = Buffer.from(sig.pk, 'base64');
            const signature = Buffer.from(sig.signature, 'base64');
            (crypt).then(data => {
                const {schnorrq, K12} = data
                const verified = schnorrq.verify(pk, message, signature)
                return res(verified)
            })
        })
    }
    const genSeed = async () => {
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
        let identity = await createIdentity(seed, 0)
        return {seed, identity}
    }
    return {
        Aes256Gcm,
        signData,
        verifySignature,
        genSeed
    }
}
window.QubicJsTools = QubicJsTools;