export function _hash(password: string): string;
export function _verify(password: string, hash: string): boolean;

export enum VerifyError {
    Unknown = 0,
    InvalidHash = 1,
}

export enum HashError {
    Unknown = 0,
}