export type JwtPayload = {
    sub: string;
    email_verified: boolean;
    iss: string;
    'cognito:username': string;
    origin_jti: string;
    aud: string;
    event_id: string;
    token_use: string;
    auth_time: string;
    exp: string;
    iat: string;
    jti: string;
    email: string;
}
