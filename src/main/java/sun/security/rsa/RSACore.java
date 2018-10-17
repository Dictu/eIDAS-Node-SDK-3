package sun.security.rsa;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.security.interfaces.RSAKey;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Map;
import java.util.WeakHashMap;

import javax.crypto.BadPaddingException;

public final class RSACore {
	
	private static final Map<BigInteger, BlindingParameters> blindingCache = new WeakHashMap<>();

	public static int getByteLength(BigInteger paramBigInteger) {
		int i = paramBigInteger.bitLength();
		return i + 7 >> 3;
	}

	public static int getByteLength(RSAKey paramRSAKey) {
		return getByteLength(paramRSAKey.getModulus());
	}

	public static byte[] convert(byte[] paramArrayOfByte, int paramInt1, int paramInt2) {
		if ((paramInt1 == 0) && (paramInt2 == paramArrayOfByte.length)) {
			return paramArrayOfByte;
		}
		byte[] arrayOfByte = new byte[paramInt2];
		System.arraycopy(paramArrayOfByte, paramInt1, arrayOfByte, 0, paramInt2);
		return arrayOfByte;
	}

	public static byte[] rsa(byte[] paramArrayOfByte, RSAPublicKey paramRSAPublicKey) throws BadPaddingException {
		return crypt(paramArrayOfByte, paramRSAPublicKey.getModulus(), paramRSAPublicKey.getPublicExponent());
	}

	@Deprecated
	public static byte[] rsa(byte[] paramArrayOfByte, RSAPrivateKey paramRSAPrivateKey) throws BadPaddingException {
		return rsa(paramArrayOfByte, paramRSAPrivateKey, true);
	}

	public static byte[] rsa(byte[] paramArrayOfByte, RSAPrivateKey paramRSAPrivateKey, boolean paramBoolean)
			throws BadPaddingException {
		if ((paramRSAPrivateKey instanceof RSAPrivateCrtKey)) {
			return crtCrypt(paramArrayOfByte, (RSAPrivateCrtKey) paramRSAPrivateKey, paramBoolean);
		}
		return priCrypt(paramArrayOfByte, paramRSAPrivateKey.getModulus(), paramRSAPrivateKey.getPrivateExponent());
	}

	private static byte[] crypt(byte[] paramArrayOfByte, BigInteger paramBigInteger1, BigInteger paramBigInteger2)
			throws BadPaddingException {
		BigInteger localBigInteger1 = parseMsg(paramArrayOfByte, paramBigInteger1);
		BigInteger localBigInteger2 = localBigInteger1.modPow(paramBigInteger2, paramBigInteger1);
		return toByteArray(localBigInteger2, getByteLength(paramBigInteger1));
	}

	private static byte[] priCrypt(byte[] paramArrayOfByte, BigInteger paramBigInteger1, BigInteger paramBigInteger2)
			throws BadPaddingException {
		BigInteger localBigInteger1 = parseMsg(paramArrayOfByte, paramBigInteger1);
		BlindingRandomPair localBlindingRandomPair = null;

		localBlindingRandomPair = getBlindingRandomPair(null, paramBigInteger2, paramBigInteger1);
		localBigInteger1 = localBigInteger1.multiply(localBlindingRandomPair.u).mod(paramBigInteger1);
		BigInteger localBigInteger2 = localBigInteger1.modPow(paramBigInteger2, paramBigInteger1);
		localBigInteger2 = localBigInteger2.multiply(localBlindingRandomPair.v).mod(paramBigInteger1);

		return toByteArray(localBigInteger2, getByteLength(paramBigInteger1));
	}

	private static byte[] crtCrypt(byte[] paramArrayOfByte, RSAPrivateCrtKey paramRSAPrivateCrtKey,
			boolean paramBoolean) throws BadPaddingException {
		BigInteger localBigInteger1 = paramRSAPrivateCrtKey.getModulus();
		BigInteger localBigInteger2 = parseMsg(paramArrayOfByte, localBigInteger1);
		BigInteger localBigInteger3 = localBigInteger2;
		BigInteger localBigInteger4 = paramRSAPrivateCrtKey.getPrimeP();
		BigInteger localBigInteger5 = paramRSAPrivateCrtKey.getPrimeQ();
		BigInteger localBigInteger6 = paramRSAPrivateCrtKey.getPrimeExponentP();
		BigInteger localBigInteger7 = paramRSAPrivateCrtKey.getPrimeExponentQ();
		BigInteger localBigInteger8 = paramRSAPrivateCrtKey.getCrtCoefficient();
		BigInteger localBigInteger9 = paramRSAPrivateCrtKey.getPublicExponent();
		BigInteger localBigInteger10 = paramRSAPrivateCrtKey.getPrivateExponent();

		BlindingRandomPair localBlindingRandomPair = getBlindingRandomPair(localBigInteger9, localBigInteger10,
				localBigInteger1);
		localBigInteger3 = localBigInteger3.multiply(localBlindingRandomPair.u).mod(localBigInteger1);

		BigInteger localBigInteger11 = localBigInteger3.modPow(localBigInteger6, localBigInteger4);

		BigInteger localBigInteger12 = localBigInteger3.modPow(localBigInteger7, localBigInteger5);

		BigInteger localBigInteger13 = localBigInteger11.subtract(localBigInteger12);
		if (localBigInteger13.signum() < 0) {
			localBigInteger13 = localBigInteger13.add(localBigInteger4);
		}
		BigInteger localBigInteger14 = localBigInteger13.multiply(localBigInteger8).mod(localBigInteger4);

		BigInteger localBigInteger15 = localBigInteger14.multiply(localBigInteger5).add(localBigInteger12);

		localBigInteger15 = localBigInteger15.multiply(localBlindingRandomPair.v).mod(localBigInteger1);
		if ((paramBoolean)
				&& (!localBigInteger2.equals(localBigInteger15.modPow(localBigInteger9, localBigInteger1)))) {
			throw new BadPaddingException("RSA private key operation failed");
		}
		return toByteArray(localBigInteger15, getByteLength(localBigInteger1));
	}

	private static BigInteger parseMsg(byte[] paramArrayOfByte, BigInteger paramBigInteger) throws BadPaddingException {
		BigInteger localBigInteger = new BigInteger(1, paramArrayOfByte);
		if (localBigInteger.compareTo(paramBigInteger) >= 0) {
			throw new BadPaddingException("Message is larger than modulus");
		}
		return localBigInteger;
	}

	private static byte[] toByteArray(BigInteger paramBigInteger, int paramInt) {
		byte[] arrayOfByte1 = paramBigInteger.toByteArray();
		int i = arrayOfByte1.length;
		if (i == paramInt) {
			return arrayOfByte1;
		}
		if ((i == paramInt + 1) && (arrayOfByte1[0] == 0)) {
			byte[] arrayOfByte2 = new byte[paramInt];
			System.arraycopy(arrayOfByte1, 1, arrayOfByte2, 0, paramInt);
			return arrayOfByte2;
		}
		assert (i < paramInt);
		byte[] arrayOfByte2 = new byte[paramInt];
		System.arraycopy(arrayOfByte1, 0, arrayOfByte2, paramInt - i, i);
		return arrayOfByte2;
	}

	private static final class BlindingRandomPair {
		final BigInteger u;
		final BigInteger v;

		BlindingRandomPair(BigInteger paramBigInteger1, BigInteger paramBigInteger2) {
			u = paramBigInteger1;
			v = paramBigInteger2;
		}
	}

	private static final class BlindingParameters {
		private static final BigInteger BIG_TWO = BigInteger.valueOf(2L);
		private final BigInteger e;
		private final BigInteger d;
		private BigInteger u;
		private BigInteger v;

		BlindingParameters(BigInteger paramBigInteger1, BigInteger paramBigInteger2, BigInteger paramBigInteger3) {
			u = null;
			v = null;
			e = paramBigInteger1;
			d = paramBigInteger2;

			int i = paramBigInteger3.bitLength();
			SecureRandom localSecureRandom = new SecureRandom();
			u = new BigInteger(i, localSecureRandom).mod(paramBigInteger3);
			if (u.equals(BigInteger.ZERO)) {
				u = BigInteger.ONE;
			}
			try {
				v = u.modInverse(paramBigInteger3);
			} catch (ArithmeticException localArithmeticException) {
				u = BigInteger.ONE;
				v = BigInteger.ONE;
			}
			if (paramBigInteger1 != null) {
				u = u.modPow(paramBigInteger1, paramBigInteger3);
			} else {
				v = v.modPow(paramBigInteger2, paramBigInteger3);
			}
		}

		RSACore.BlindingRandomPair getBlindingRandomPair(BigInteger paramBigInteger1, BigInteger paramBigInteger2,
				BigInteger paramBigInteger3) {
			if (((e != null) && (e.equals(paramBigInteger1))) || ((d != null) && (d.equals(paramBigInteger2)))) {
				RSACore.BlindingRandomPair localBlindingRandomPair = null;
				synchronized (this) {
					if ((!u.equals(BigInteger.ZERO)) && (!v.equals(BigInteger.ZERO))) {
						localBlindingRandomPair = new RSACore.BlindingRandomPair(u, v);
						if ((u.compareTo(BigInteger.ONE) <= 0) || (v.compareTo(BigInteger.ONE) <= 0)) {
							u = BigInteger.ZERO;
							v = BigInteger.ZERO;
						} else {
							u = u.modPow(BIG_TWO, paramBigInteger3);
							v = v.modPow(BIG_TWO, paramBigInteger3);
						}
					}
				}
				return localBlindingRandomPair;
			}
			return null;
		}
	}

	private static BlindingRandomPair getBlindingRandomPair(BigInteger paramBigInteger1, BigInteger paramBigInteger2, BigInteger paramBigInteger3)
  {
    BlindingParameters localBlindingParameters = null;
    synchronized (blindingCache)
    {
      localBlindingParameters = (BlindingParameters)blindingCache.get(paramBigInteger3);
    }
    if (localBlindingParameters == null)
    {
      localBlindingParameters = new BlindingParameters(paramBigInteger1, paramBigInteger2, paramBigInteger3);
      synchronized (blindingCache)
      {
        blindingCache.putIfAbsent(paramBigInteger3, localBlindingParameters);
      }
    }
    RSACore.BlindingRandomPair pair = localBlindingParameters.getBlindingRandomPair(paramBigInteger1, paramBigInteger2, paramBigInteger3);
    if (pair == null)
    {
      localBlindingParameters = new BlindingParameters(paramBigInteger1, paramBigInteger2, paramBigInteger3);
      synchronized (blindingCache)
      {
        blindingCache.replace(paramBigInteger3, localBlindingParameters);
      }
      pair = localBlindingParameters.getBlindingRandomPair(paramBigInteger1, paramBigInteger2, paramBigInteger3);
    }
    return (BlindingRandomPair)pair;
  }
}