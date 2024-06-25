import { b64encode } from 'k6/encoding';
import { Options } from 'k6/options';
import { randEmail, randUuid, randNumber, randFloat, randRecentDate } from '@ngneat/falso';
import { JwtPayload } from "./util-test";

import { sleep, check } from 'k6';
import http from 'k6/http';
import crypto from "k6/crypto";
import encoding from "k6/encoding";


export let options: Options = {
    vus: 10,
    duration: '60s'
};

const ISSUER_PLACEHOLDER = "test.org"
const SECRET = `secret`




let TS_SEC = Math.floor(Date.now() / 1000);
let TS = Date.now();

function getRandomInt(min = 0, max = 1): number {
    return Math.floor(Math.random() * (max - min + 1)) + min;
}
function sign(data: string, secret: string) {
    let hasher = crypto.createHMAC("sha256", secret);
    hasher.update(data);

    // Some manual base64 rawurl encoding as `Hasher.digest(encodingType)`
    // doesn't support that encoding type yet.
    return hasher.digest("base64").replace(/\//g, "_").replace(/\+/g, "-").replace(/=/g, "");
}

function encode(payload: object, secret: string) {
    let header = encoding.b64encode(JSON.stringify({ typ: "JWT", alg: "HS256" }), "rawurl");
    const encodedPayload = encoding.b64encode(JSON.stringify(payload), "rawurl");
    let sig = sign(header + "." + encodedPayload, secret);
    return [header, encodedPayload, sig].join(".");
}


function generateSessionData(): string {
    const filenames: string[] = []

    for (let i = 0; i < randNumber({ min: 240, max: 550 }); i++) {
        const filename = genarateSessionDataFilename(TS += getRandomInt(60, 120))
        filenames.push(filename);
    }

    const concatenatedFilenames = filenames.join(',');

    return b64encode(concatenatedFilenames);
}


function genarateSessionDataFilename(timestamp: number): string {

    const randomSnoreData = randNumber({ min: 0, max: 10 })
    let createNoneSnore = true

    if (randomSnoreData === 3) {
        createNoneSnore = false
    }

    let randomInteger = randNumber({ min: 1, max: 100 })

    if (createNoneSnore) randomInteger = 0;

    const floatValue1 = randFloat({ min: 30, max: 60, fraction: 2 })
    const floatValue2 = randFloat({ min: 40, max: 80, fraction: 2 })

    let randomInteger2 = randNumber({ min: 10, max: 90 })
    let randomInteger3 = randNumber({ min: 10, max: 90 })

    const floatValue3 = randFloat({ min: 31, max: 90, fraction: 3 })
    const floatValue4 = randFloat({ min: 36, max: 90, fraction: 2 })
    const floatValue5 = randFloat({ min: 25, max: 90, fraction: 2 })
    const floatValue6 = randFloat({ min: 30, max: 60, fraction: 2 })

    if (createNoneSnore) {
        return `${timestamp}-${randomInteger}-${floatValue1}-${floatValue2}-null-NMSnore-NAvgSnore-${floatValue5}`
    }

    return `${timestamp}-${randomInteger}-${floatValue1}-${floatValue2}-[${randomInteger2}-${randomInteger3}-${floatValue3}]-${floatValue4}-${floatValue5}-${floatValue6}`
}




export default () => {
    let message: JwtPayload = {
        sub: randUuid(),
        email_verified: true,
        iss: ISSUER_PLACEHOLDER,
        "cognito:username": randUuid(),
        origin_jti: randUuid(),
        aud: ISSUER_PLACEHOLDER,
        event_id: randUuid(),
        token_use: "id",
        auth_time: TS_SEC,
        exp: TS_SEC + 3600,
        iat: TS_SEC,
        jti: TS_SEC,
        email: randEmail()
    };

    let token = encode(message, SECRET);



    const sessionData = generateSessionData()


    const randomDate = randRecentDate({ days: 30 });
    const randomDateString = randomDate.toISOString().split('T')[0]

    const res = http.get(`http://localhost:4000/users/me`, {
        headers: {
            'Content-Type': 'application/json',
            Authorization: `Bearer ${token}`,
        }
    });

    sleep(3);


    const sessionLength = randNumber({ min: 240, max: 550 });
    console.log(randomDate.getTime());

    const data = {
        sessionData: sessionData,
        actionEventCount: randNumber({ min: 0, max: sessionLength }),
        actionCount: randNumber({ min: 0, max: sessionLength * 10 }),
        isPebbleUsed: true,
        lightCount: randNumber({ min: 0, max: 400 }),
        quietCount: randNumber({ min: 0, max: 400 }),
        severeCount: randNumber({ min: 0, max: 400 }),
        loudCount: randNumber({ min: 0, max: 400 }),
        totalSessionDuration: sessionLength,
        sessionEndTime: randomDate.getTime(),
        sessionStartTime: randomDate.getTime() - sessionLength * 100,
    }

    const sessionEndRes = http.post(`http://localhost:4000/sessions/${randomDateString}`, JSON.stringify(data), {
        headers: {
            'Content-Type': 'application/json',
            Authorization: `Bearer ${token}`,
        },
    })


    check(res, {
        'status is 200 - GET USERS ME': () => res.status === 200,
        'status is 201 - POST SESSION': () => sessionEndRes.status === 201,
    });
    sleep(1);
}

