import { generateKeyPairSync, createSign, createVerify, publicEncrypt, privateDecrypt } from 'crypto';

const generateKeyPair = () => {
    const { publicKey, privateKey } = generateKeyPairSync('rsa', {
        modulusLength: 2048
    });
    return { publicKey, privateKey };
};

const createSignature = (data, privateKey) => {
    const sign = createSign('SHA256');
    sign.update(data);
    sign.end();
    return sign.sign(privateKey, 'base64');
};

const verifySignature = (data, signature, publicKey) => {
    const verify = createVerify('SHA256');
    verify.update(data);
    verify.end();
    return verify.verify(publicKey, signature, 'base64');
};

const encryptData = (data, publicKey) => {
    return publicEncrypt(publicKey, Buffer.from(data)).toString('base64');
};

const decryptData = (encryptedData, privateKey) => {
    return privateDecrypt(privateKey, Buffer.from(encryptedData, 'base64')).toString();
};

const { publicKey, privateKey } = generateKeyPair();
const data = "Something...";

console.log("================================================================\n");

const signature = createSignature(data, privateKey);
console.log(`Sign: ${signature}\n`);

const isValidSignature = verifySignature(data, signature, publicKey);
console.log(`Sign ${isValidSignature ? "is" : "is not"} valid\n`);

console.log("================================================================\n\n\n");

console.log("================================================================\n");

const encryptedData = encryptData(data, publicKey);
console.log(`Encrypted data: ${encryptedData}\n`);

const decryptedData = decryptData(encryptedData, privateKey);
console.log(`Decrypted data: ${decryptedData}\n`);

console.log("================================================================");