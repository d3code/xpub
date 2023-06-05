/*
  This script uses version bytes as described in SLIP-132
  https://github.com/satoshilabs/slips/blob/master/slip-0132.md
*/
let b58 = require('bs58check');
let bip32 = require('bip32');

const prefixes = new Map(
    [
        ['xpub', '0488b21e'],
        ['ypub', '049d7cb2'],
        ['Ypub', '0295b43f'],
        ['zpub', '04b24746'],
        ['Zpub', '02aa7ed3'],
        ['tpub', '043587cf'],
        ['upub', '044a5262'],
        ['Upub', '024289ef'],
        ['vpub', '045f1cf6'],
        ['Vpub', '02575483'],
    ]
);

const NETWORK_TYPES = {
    "xpub": {
        bech32: 'bc',
        bip32: {
            public: 0x0488b21e,
            private: 0x0488ade4,
        },
        pubKeyHash: 0x00,
        scriptHash: 0x05,
        wif: 0x80,
    },
    "ypub": {
        bech32: 'bc',
        bip32: {
            public: 0x049d7cb2,
            private: 0x049d7878,
        },
        pubKeyHash: 0x00,
        scriptHash: 0x05,
        wif: 0x80,
    },
    "Ypub": {
        bech32: 'bc',
        bip32: {
            public: 0x0295b43f,
            private: 0x0295b005,
        },
        pubKeyHash: 0x00,
        scriptHash: 0x05,
        wif: 0x80,
    },
    "zpub": {
        bech32: 'bc',
        bip32: {
            public: 0x04b24746,
            private: 0x04b2430c,
        },
        pubKeyHash: 0x00,
        scriptHash: 0x05,
        wif: 0x80,
    },
    "Zpub": {
        bech32: 'bc',
        bip32: {
            public: 0x02aa7ed3,
            private: 0x02aa7a99,
        },
        pubKeyHash: 0x00,
        scriptHash: 0x05,
        wif: 0x80,
    },
    "tpub": {
        bech32: 'tb',
        bip32: {
            public: 0x043587cf,
            private: 0x04358394,
        },
        pubKeyHash: 0x6f,
        scriptHash: 0xc4,
        wif: 0xef,
    },
    "upub": {
        bech32: 'tb',
        bip32: {
            public: 0x044a5262,
            private: 0x044a4e28,
        },
        pubKeyHash: 0x6f,
        scriptHash: 0xc4,
        wif: 0xef,
    },
    "Upub": {
        bech32: 'tb',
        bip32: {
            public: 0x024289ef,
            private: 0x024285b5,
        },
        pubKeyHash: 0x6f,
        scriptHash: 0xc4,
        wif: 0xef,
    },
    "vpub": {
        bech32: 'tb',
        bip32: {
            public: 0x045f1cf6,
            private: 0x045f18bc,
        },
        pubKeyHash: 0x6f,
        scriptHash: 0xc4,
        wif: 0xef,
    },
    "Vpub": {
        bech32: 'tb',
        bip32: {
            public: 0x02575483,
            private: 0x02575048,
        },
        pubKeyHash: 0x6f,
        scriptHash: 0xc4,
        wif: 0xef,
    }
};

function byteArrayToHexString(byteArray) {
    return Array.from(byteArray, function(byte) {
        return ('0' + (byte & 0xFF).toString(16)).slice(-2);
    }).join('')
}

/*
 * This function takes an extended public key (with any version bytes, it doesn't need to be an xpub)
 * and converts it to an extended public key formatted with the desired version bytes
 * @param xpub: an extended public key in base58 format. Example: xpub6CpihtY9HVc1jNJWCiXnRbpXm5BgVNKqZMsM4XqpDcQigJr6AHNwaForLZ3kkisDcRoaXSUms6DJNhxFtQGeZfWAQWCZQe1esNetx5Wqe4M
 * @param targetFormat: a string representing the desired prefix; must exist in the "prefixes" mapping defined above. Example: Zpub
*/
convertPublicKey = function(targetFormat, xpub) {
    if (!prefixes.has(targetFormat)) {
        return "Invalid target version";
    }

    xpub = xpub.trim();

    try {
        let data = b58.decode(xpub);
        data = data.slice(4);
        data = Buffer.concat([Buffer.from(prefixes.get(targetFormat),'hex'), data]);
        return b58.encode(data);
    } catch (err) {
        return "Invalid extended public key! Please double check that you didn't accidentally paste extra data.";
    }
}

getFingerprint = function(targetFormat, xpub) {
    return byteArrayToHexString(bip32.fromBase58(convertPublicKey(targetFormat, xpub), NETWORK_TYPES[targetFormat]).fingerprint);
}

getParentFingerprint = function(targetFormat, xpub) {
    return bip32.fromBase58(convertPublicKey(targetFormat, xpub), NETWORK_TYPES[targetFormat]).parentFingerprint.toString(16);
}

getDepth = function(targetFormat, xpub) {
    return bip32.fromBase58(convertPublicKey(targetFormat, xpub), NETWORK_TYPES[targetFormat]).depth;
}


x = convertPublicKey("ypub", "xpub6DJiysHdcBrzncJFDqynreiUfL29N2hdcofUubFUcujobjnDS3Vc5uHQvNBAF7qYezvqUG6VP8JHWgG5QRAC39F3RroovwZfm4otNTbsauZ");
console.log(x);
