import {createIdentity, privateKey, crypto as crypt} from 'qubic-js'
import crypto from "crypto";
const aes = require('browserify-aes')
const pbkdf2 = require('pbkdf2')
const SEED_ALPHABET = 'abcdefghijklmnopqrstuvwxyz';
const PRIVATE_KEY_LENGTH = 32;
export const PUBLIC_KEY_LENGTH = 32;
export const CHECKSUM_LENGTH = 3;
const algorithm = 'aes-256-cbc';

window.signData = async (seed, data) => {
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

window.verifySignature = (message, sig) => {
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

window.decrypt = (encrypted, password) => {
    return new Promise((res, rej) => {
        try {
            if(!encrypted.hasOwnProperty('ct') || !encrypted.hasOwnProperty('salt') || !encrypted.hasOwnProperty('iv')) {
                return rej('Malformed JSON Message to Decrypt')
            }
            let { ct, salt, iv } = encrypted
            iv = Buffer.from(iv, 'base64')
            const derivedKey = pbkdf2.pbkdf2Sync(password, salt, 1, 32, 'sha512')
            const decipher = crypto.createDecipheriv(algorithm, derivedKey, iv)
            return res(decipher.update(ct, 'base64', 'utf8') + decipher.final('utf8'))
        } catch(error) {
            return rej(error)
        }
    })
}

window.encrypt = (data, password, iv = null) => {
    return new Promise((res, rej) => {
        try {
            if(!iv) {
                iv = crypto.randomBytes(16);   //16 byte IV
            }
            const salt = Buffer.from(crypto.randomBytes(16)).toString('base64')
            const derivedKey = pbkdf2.pbkdf2Sync(password, salt, 1, 32, 'sha512')
            const cipher = crypto.createCipheriv(algorithm, derivedKey, iv)
            const ct = cipher.update(data, 'utf8', 'base64') + cipher.final('base64')
            return res({ct, salt, iv: Buffer.from(iv).toString('base64')})
        } catch(error) {
            return rej(error)
        }
    })
}

window.genSeed = async () => {
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