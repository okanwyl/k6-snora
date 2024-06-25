import crypto, { Algorithm } from "k6/crypto";
import encoding, { b64encode } from "k6/encoding";
import { Options } from 'k6/options';
import { randDomainName, randEmail, randUuid, randNumber, randFloat } from '@ngneat/falso';
import { JwtPayload } from "./util-test";

import { sleep, check } from 'k6';
import http from 'k6/http';

const SECRET = "secret"

export let options: Options = {
    vus: 10,
    duration: '60s'
};


let TS = Date.now();

function getRandomInt(min = 0, max = 1): number {
    return Math.floor(Math.random() * (max - min + 1)) + min;
}


function sign(data: string, hashAlg: Algorithm, secret: string): string {
    let hasher = crypto.createHMAC(hashAlg, secret);
    hasher.update(data);

    // Some manual base64 rawurl encoding as `Hasher.digest(encodingType)`
    // doesn't support that encoding type yet.
    return hasher.digest("base64").replace(/\//g, "_").replace(/\+/g, "-").replace(/=/g, "");
}

function encode(payload: object, secret: string, algorithm: Algorithm): string {
    let header = encoding.b64encode(JSON.stringify({ typ: "JWT", alg: algorithm }), "rawurl");
    let payloadString = JSON.stringify(payload);
    let encodedPayload = encoding.b64encode(payloadString, "rawurl");
    let sig = sign(header + "." + encodedPayload, algorithm, secret);
    return [header, encodedPayload, sig].join(".");
}

//def generate_filename(timestamp):
//    random_snore_data = random.randint(0, 10)
//    create_none_snore = True
//    if random_snore_data == 3:
//        create_none_snore = False
//
//    random_int = random.randint(1, 100)
//    if create_none_snore:
//        random_int = 0
//
//    # Db values
//    ranndom_float_2f = round(random.uniform(30.00, 60.00), 2)
//    ranndom_float_2f_2 = round(random.uniform(40.00, 80.00), 2)
//
//    random_int_2 = random.randint(10, 90)
//    random_int_3 = random.randint(10, 90)
//
//    # snore event m4a
//    random_float_3f = round(random.uniform(30.39, 90.04), 3)
//    random_float_2f_3 = round(random.uniform(36.39, 90.04), 2)
//    random_float_2f_4 = round(random.uniform(25.39, 90.04), 2)
//    random_float_2f_5 = round(random.uniform(30.00, 60.00), 2)
//
//    if create_none_snore:
//        return f"{timestamp}-{str(random_int)}-{str(ranndom_float_2f)}-{str(ranndom_float_2f_2)}-null-NMSnore-NAvgSnore-{str(random_float_2f_5)}"
//
//    return f"{timestamp}-{str(random_int)}-{str(ranndom_float_2f)}-{str(ranndom_float_2f_2)}-[{str(random_int_2)}-{str(random_int_3)}-{str(random_float_3f)}]-{str(random_float_2f_3)}-{str(random_float_2f_4)}-{str(random_float_2f_5)}"
//
//
//def generate_unixtimestamp(date_string):
//    # Convert the date string to a datetime object
//    date = datetime.datetime.strptime(date_string, "%Y-%m-%d")
//
//    # Get the current time
//    current_time = datetime.datetime.now().time()
//
//    # Combine the date and time
//    current_datetime = datetime.datetime.combine(date.date(), current_time)
//
//    # Convert the datetime to Unix timestamp
//    unix_timestamp = int(current_datetime.timestamp())
//
//    return unix_timestamp
//
//
//def generate_list(datetime):
//    current_time = generate_unixtimestamp(datetime)
//    filenames = []
//    for i in range(500):
//        current_time = current_time + 100
//        filename = generate_filename(current_time)
//        filenames.append(filename)
//    return filenames
//
//

function generateSessionData(timestamp: string): string {
    const filenames: string[] = []

    for (let i = 0; i < randNumber({ min: 240, max: 550 }); i++) {
        const filename = genarateSessionDataFilename(timestamp)
        filenames.push(filename);
    }

    const concatenatedFilenames = filenames.join(',');

    return b64encode(concatenatedFilenames);
}


function genarateSessionDataFilename(timestamp: string): string {

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
        iss: randDomainName(),
        "cognito:username": randUuid(),
        origin_jti: randUuid(),
        aud: randUuid(),
        event_id: randUuid(),
        token_use: "id",
        auth_time: String(TS += getRandomInt(60, 120)),
        exp: String(TS += getRandomInt(60, 120)),
        iat: String(TS += getRandomInt(60, 120)),
        jti: String(TS += getRandomInt(60, 120)),
        email: randEmail()
    };


    //console.log(TS += getRandomInt(60, 120))
    console.log(generateSessionData(String(TS += getRandomInt(60, 120))))

    const alg: Algorithm = "sha256"

    const token = encode(message, SECRET, alg);
    //console.log(genarateSessionDataFilename(String(TS)));

    const options = {
        headers: {
            Authorization: `Bearer ${token}`,
        },
    };

    const res = http.get('http://localhost:4000', options);

    //console.log(user);
    console.log(message);

    check(res, {
        'status is 200': () => res.status === 200,
    });
    sleep(1);
}

