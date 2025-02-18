package de.gematik.openhealth.crypto.key

import com.ionspin.kotlin.bignum.integer.BigInteger
import com.ionspin.kotlin.bignum.integer.base63.toJavaBigInteger

import org.bouncycastle.jce.ECNamedCurveTable

internal actual fun EcPoint.nativeTimes(k: BigInteger): EcPoint {
    val ecSpec = ECNamedCurveTable.getParameterSpec(curve.name)
    val ecPoint = ecSpec.curve.decodePoint(uncompressed)
    val result = ecPoint.multiply(k.toJavaBigInteger())
    val uncompressedEcPoint = result.getEncoded(false)
    return EcPublicKey(curve, uncompressedEcPoint).toEcPoint()
}

internal actual fun EcPoint.nativePlus(other: EcPoint): EcPoint {
    val ecSpec = ECNamedCurveTable.getParameterSpec(curve.name)
    val ecPoint = ecSpec.curve.decodePoint(uncompressed)
    val otherEcPoint = ecSpec.curve.decodePoint(other.uncompressed)
    val result = ecPoint.add(otherEcPoint)
    val uncompressedEcPoint = result.getEncoded(false)
    return EcPublicKey(curve, uncompressedEcPoint).toEcPoint()
}