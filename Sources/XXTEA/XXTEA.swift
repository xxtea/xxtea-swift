//
//  XXTEA.swift
//  XXTEA
//
//  Created by 马秉尧 on 2025/9/10.
//

import Foundation

class XXTEA {
    private static let delta: UInt32 = 0x9E3779B9
    @inline(__always) private static func mx(_ sum: UInt32, _ y: UInt32, _ z: UInt32, _ p: Int, _ e: UInt32, _ k: [UInt32]) -> UInt32 {
        return ((z >> 5 ^ y << 2) &+ (y >> 3 ^ z << 4)) ^ ((sum ^ y) &+ (k[p & 3 ^ Int(e)] ^ z))
    }
    public static func encrypt(_ data: Data, key: Data) -> Data {
        if data.isEmpty {
            return data
        }
        var v = toUInt32Array(data, true)
        let k = toUInt32Array(fixKey(key), false)
        return toData(enctypt(&v, k), false)
    }
    public static func encrypt(_ data: Data, stringKey: String) -> Data {
        return encrypt(data, key: stringKey.data(using: .utf8)!)
    }
    public static func encryptString(_ stringData: String, key: Data) -> Data {
        return encrypt(stringData.data(using: .utf8)!, key: key)
    }
    public static func encryptString(_ stringData: String, stringKey: String) -> Data {
        return encrypt(stringData.data(using: .utf8)!, key: stringKey.data(using: .utf8)!)
    }
    public static func decrypt(_ data: Data, key: Data) -> Data {
        if data.isEmpty {
            return data
        }
        var v = toUInt32Array(data, false)
        let k = toUInt32Array(fixKey(key), false)
        return toData(decrypt(&v, k), true)
    }
    public static func decrypt(_ data: Data, stringKey: String) -> Data {
        return decrypt(data, key: stringKey.data(using: .utf8)!)
    }
    public static func decryptToString(_ data: Data, key: Data) -> String? {
        return String(data: decrypt(data, key: key), encoding: .utf8)
    }
    public static func decryptToString(_ data: Data, stringKey: String) -> String? {
        return String(data: decrypt(data, key: stringKey.data(using: .utf8)!), encoding: .utf8)
    }

    private static func fixKey(_ key: Data) -> Data {
        if key.count == 16 {
            return key
        }
        var fixedKey = Data(count: 16)
        fixedKey.withUnsafeMutableBytes {
            key.copyBytes(to: $0.bindMemory(to: UInt8.self).baseAddress!, count: min(key.count, 16))
        }
        return fixedKey
    }
    private static func toUInt32Array(_ data: Data, _ includeLength: Bool) -> [UInt32] {
        let length = data.count
        let n = (((length & 3) == 0) ? (length >> 2) : ((length >> 2) + 1))
        var result: [UInt32]
        if includeLength {
            result = Array(repeating: 0, count: n+1)
            result[n] = UInt32(length)
        } else {
            result = Array(repeating: 0, count: n)
        }
        for i in 0..<length {
            result[i >> 2] |= UInt32(data[i]) << ((i & 3) << 3)
        }
        return result
    }
    private static func toData(_ data: [UInt32], _ includeLength: Bool) -> Data {
        var n = data.count << 2
        if includeLength {
            let m = Int(data[data.count - 1])
            n -= 4
            if ((m < n - 3) || (m > n)) {
                return Data()
            }
            n = m
        }
        var result = Data(count: n)
        for i in 0..<n {
            result[i] = UInt8((data[i >> 2] >> ((i & 3) << 3)) & 0xFF)
        }
        return result
    }
    private static func enctypt(_ v: inout [UInt32], _ k: [UInt32]) -> [UInt32] {
        let n = v.count - 1
        if n < 1 {
            return v
        }
        var z = v[n]
        var y: UInt32
        var sum: UInt32 = 0
        var e: UInt32
        var q = 6 + 52 / (n + 1)
        while 0 < q {
            q-=1
            sum &+= delta
            e = sum >> 2 & 3
            for p in 0..<n {
                y = v[p + 1]
                v[p] &+= mx(sum, y, z, p, e, k)
                z = v[p]
            }
            y = v[0]
            v[n] &+= mx(sum, y, z, n, e, k)
            z = v[n]
        }
        return v
    }
    private static func decrypt(_ v: inout [UInt32], _ k: [UInt32]) -> [UInt32] {
        let n = v.count - 1
        if (n < 1) {
            return v
        }
        var z: UInt32
        var y = v[0]
        var e: UInt32
        let q = 6 + 52 / (n + 1)
        var sum = UInt32(q) &* delta
        while (sum != 0) {
            e = sum >> 2 & 3
            for p in stride(from: n, to: 0, by: -1) {
                z = v[p - 1]
                v[p] &-= mx(sum, y, z, p, e, k)
                y = v[p]
            }
            z = v[n]
            v[0] &-= mx(sum, y, z, 0, e, k)
            y = v[0]
            sum &-= delta
        }
        return v
    }
}
