package sun.security.rsa;

import java.security.DigestException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.MGF1ParameterSpec;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import javax.crypto.BadPaddingException;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;

public final class RSAPadding
{
  public static final int PAD_BLOCKTYPE_1 = 1;
  public static final int PAD_BLOCKTYPE_2 = 2;
  public static final int PAD_NONE = 3;
  public static final int PAD_OAEP_MGF1 = 4;
  private final int type;
  private final int paddedSize;
  private SecureRandom random;
  private final int maxDataSize;
  private MessageDigest md;
  private MessageDigest mgfMd;
  private byte[] lHash;
  
  public static RSAPadding getInstance(int paramInt1, int paramInt2)
    throws InvalidKeyException, InvalidAlgorithmParameterException
  {
    return new RSAPadding(paramInt1, paramInt2, null, null);
  }
  
  public static RSAPadding getInstance(int paramInt1, int paramInt2, SecureRandom paramSecureRandom)
    throws InvalidKeyException, InvalidAlgorithmParameterException
  {
    return new RSAPadding(paramInt1, paramInt2, paramSecureRandom, null);
  }
  
  public static RSAPadding getInstance(int paramInt1, int paramInt2, SecureRandom paramSecureRandom, OAEPParameterSpec paramOAEPParameterSpec)
    throws InvalidKeyException, InvalidAlgorithmParameterException
  {
    return new RSAPadding(paramInt1, paramInt2, paramSecureRandom, paramOAEPParameterSpec);
  }
  
  private RSAPadding(int paramInt1, int paramInt2, SecureRandom paramSecureRandom, OAEPParameterSpec paramOAEPParameterSpec)
    throws InvalidKeyException, InvalidAlgorithmParameterException
  {
    type = paramInt1;
    paddedSize = paramInt2;
    random = paramSecureRandom;
    if (paramInt2 < 64) {
      throw new InvalidKeyException("Padded size must be at least 64");
    }
    switch (paramInt1)
    {
    case 1: 
    case 2: 
      maxDataSize = (paramInt2 - 11);
      break;
    case 3: 
      maxDataSize = paramInt2;
      break;
    case 4: 
      String str1 = "SHA-1";
      String str2 = "SHA-1";
      byte[] arrayOfByte = null;
      try
      {
        if (paramOAEPParameterSpec != null)
        {
          str1 = paramOAEPParameterSpec.getDigestAlgorithm();
          String str3 = paramOAEPParameterSpec.getMGFAlgorithm();
          if (!str3.equalsIgnoreCase("MGF1")) {
            throw new InvalidAlgorithmParameterException("Unsupported MGF algo: " + str3);
          }
          str2 = ((MGF1ParameterSpec)paramOAEPParameterSpec.getMGFParameters()).getDigestAlgorithm();
          PSource localPSource = paramOAEPParameterSpec.getPSource();
          String str4 = localPSource.getAlgorithm();
          if (!str4.equalsIgnoreCase("PSpecified")) {
            throw new InvalidAlgorithmParameterException("Unsupported pSource algo: " + str4);
          }
          arrayOfByte = ((PSource.PSpecified)localPSource).getValue();
        }
        md = MessageDigest.getInstance(str1);
        mgfMd = MessageDigest.getInstance(str2);
      }
      catch (NoSuchAlgorithmException localNoSuchAlgorithmException)
      {
        throw new InvalidKeyException("Digest " + str1 + " not available", localNoSuchAlgorithmException);
      }
      lHash = getInitialHash(md, arrayOfByte);
      int i = lHash.length;
      maxDataSize = (paramInt2 - 2 - 2 * i);
      if (maxDataSize <= 0) {
        throw new InvalidKeyException("Key is too short for encryption using OAEPPadding with " + str1 + " and MGF1" + str2);
      }
      break;
    default: 
      throw new InvalidKeyException("Invalid padding: " + paramInt1);
    }
  }
  
  private static final Map<String, byte[]> emptyHashes = Collections.synchronizedMap(new HashMap<>());
  
  private static byte[] getInitialHash(MessageDigest paramMessageDigest, byte[] paramArrayOfByte)
  {
    byte[] arrayOfByte;
    if ((paramArrayOfByte == null) || (paramArrayOfByte.length == 0))
    {
      String str = paramMessageDigest.getAlgorithm();
      arrayOfByte = (byte[])emptyHashes.get(str);
      if (arrayOfByte == null)
      {
        arrayOfByte = paramMessageDigest.digest();
        emptyHashes.put(str, arrayOfByte);
      }
    }
    else
    {
      arrayOfByte = paramMessageDigest.digest(paramArrayOfByte);
    }
    return arrayOfByte;
  }
  
  public int getMaxDataSize()
  {
    return maxDataSize;
  }
  
  public byte[] pad(byte[] paramArrayOfByte, int paramInt1, int paramInt2)
    throws BadPaddingException
  {
    return pad(RSACore.convert(paramArrayOfByte, paramInt1, paramInt2));
  }
  
  public byte[] pad(byte[] paramArrayOfByte)
    throws BadPaddingException
  {
    if (paramArrayOfByte.length > maxDataSize) {
      throw new BadPaddingException("Data must be shorter than " + (maxDataSize + 1) + " bytes");
    }
    switch (type)
    {
    case 3: 
      return paramArrayOfByte;
    case 1: 
    case 2: 
      return padV15(paramArrayOfByte);
    case 4: 
      return padOAEP(paramArrayOfByte);
    }
    throw new AssertionError();
  }
  
  public byte[] unpad(byte[] paramArrayOfByte, int paramInt1, int paramInt2)
    throws BadPaddingException
  {
    return unpad(RSACore.convert(paramArrayOfByte, paramInt1, paramInt2));
  }
  
  public byte[] unpad(byte[] paramArrayOfByte)
    throws BadPaddingException
  {
    if (paramArrayOfByte.length != paddedSize) {
      throw new BadPaddingException("Decryption error");
    }
    switch (type)
    {
    case 3: 
      return paramArrayOfByte;
    case 1: 
    case 2: 
      return unpadV15(paramArrayOfByte);
    case 4: 
      return unpadOAEP(paramArrayOfByte);
    }
    throw new AssertionError();
  }
  
  private byte[] padV15(byte[] paramArrayOfByte)
    throws BadPaddingException
  {
    byte[] arrayOfByte1 = new byte[paddedSize];
    System.arraycopy(paramArrayOfByte, 0, arrayOfByte1, paddedSize - paramArrayOfByte.length, paramArrayOfByte.length);
    
    int i = paddedSize - 3 - paramArrayOfByte.length;
    int j = 0;
    arrayOfByte1[(j++)] = 0;
    arrayOfByte1[(j++)] = ((byte)type);
    if (type == 1) {
      while (i-- > 0) {
        arrayOfByte1[(j++)] = -1;
      }
    }
    if (random == null) {
      random = new SecureRandom();
    }
    byte[] arrayOfByte2 = new byte[64];
    int k = -1;
    while (i-- > 0)
    {
      int m;
      do
      {
        if (k < 0)
        {
          random.nextBytes(arrayOfByte2);
          k = arrayOfByte2.length - 1;
        }
        m = arrayOfByte2[(k--)] & 0xFF;
      } while (m == 0);
      arrayOfByte1[(j++)] = ((byte)m);
    }
    return arrayOfByte1;
  }
  
  private byte[] unpadV15(byte[] paramArrayOfByte)
    throws BadPaddingException
  {
    int i = 0;
    int j = 0;
    if (paramArrayOfByte[(i++)] != 0) {
      j = 1;
    }
    if (paramArrayOfByte[(i++)] != type) {
      j = 1;
    }
    int k = 0;
    while (i < paramArrayOfByte.length)
    {
     int m = paramArrayOfByte[(i++)] & 0xFF;
      if ((m == 0) && (k == 0)) {
        k = i;
      }
      if ((i == paramArrayOfByte.length) && (k == 0)) {
        j = 1;
      }
      if ((type == 1) && (m != 255) && (k == 0)) {
        j = 1;
      }
    }
    int m = paramArrayOfByte.length - k;
    if (m > maxDataSize) {
      j = 1;
    }
    byte[] arrayOfByte1 = new byte[k];
    System.arraycopy(paramArrayOfByte, 0, arrayOfByte1, 0, k);
    
    byte[] arrayOfByte2 = new byte[m];
    System.arraycopy(paramArrayOfByte, k, arrayOfByte2, 0, m);
    
    BadPaddingException localBadPaddingException = new BadPaddingException("Decryption error");
    if (j != 0) {
      throw localBadPaddingException;
    }
    return arrayOfByte2;
  }
  
  private byte[] padOAEP(byte[] paramArrayOfByte)
    throws BadPaddingException
  {
    if (random == null) {
      random = new SecureRandom();
    }
    int i = lHash.length;
    


    byte[] arrayOfByte1 = new byte[i];
    random.nextBytes(arrayOfByte1);
    

    byte[] arrayOfByte2 = new byte[paddedSize];
    

    int j = 1;
    int k = i;
    

    System.arraycopy(arrayOfByte1, 0, arrayOfByte2, j, k);
    


    int m = i + 1;
    int n = arrayOfByte2.length - m;
    

    int i1 = paddedSize - paramArrayOfByte.length;
    





    System.arraycopy(lHash, 0, arrayOfByte2, m, i);
    arrayOfByte2[(i1 - 1)] = 1;
    System.arraycopy(paramArrayOfByte, 0, arrayOfByte2, i1, paramArrayOfByte.length);
    

    mgf1(arrayOfByte2, j, k, arrayOfByte2, m, n);
    

    mgf1(arrayOfByte2, m, n, arrayOfByte2, j, k);
    
    return arrayOfByte2;
  }
  
  private byte[] unpadOAEP(byte[] paramArrayOfByte)
    throws BadPaddingException
  {
    byte[] arrayOfByte1 = paramArrayOfByte;
    int i = 0;
    int j = lHash.length;
    if (arrayOfByte1[0] != 0) {
      i = 1;
    }
    int k = 1;
    int m = j;
    
    int n = j + 1;
    int i1 = arrayOfByte1.length - n;
    
    mgf1(arrayOfByte1, n, i1, arrayOfByte1, k, m);
    mgf1(arrayOfByte1, k, m, arrayOfByte1, n, i1);
    for (int i2 = 0; i2 < j; i2++) {
      if (lHash[i2] != arrayOfByte1[(n + i2)]) {
        i = 1;
      }
    }
    int i2 = n + j;
    int i3 = -1;
    for (int i4 = i2; i4 < arrayOfByte1.length; i4++)
    {
      int i5 = arrayOfByte1[i4];
      if ((i3 == -1) && 
        (i5 != 0)) {
        if (i5 == 1) {
          i3 = i4;
        } else {
          i = 1;
        }
      }
    }
    if (i3 == -1)
    {
      i = 1;
      i3 = arrayOfByte1.length - 1;
    }
    int i4 = i3 + 1;
    

    byte[] arrayOfByte2 = new byte[i4 - i2];
    System.arraycopy(arrayOfByte1, i2, arrayOfByte2, 0, arrayOfByte2.length);
    
    byte[] arrayOfByte3 = new byte[arrayOfByte1.length - i4];
    System.arraycopy(arrayOfByte1, i4, arrayOfByte3, 0, arrayOfByte3.length);
    
    BadPaddingException localBadPaddingException = new BadPaddingException("Decryption error");
    if (i != 0) {
      throw localBadPaddingException;
    }
    return arrayOfByte3;
  }
  
  private void mgf1(byte[] paramArrayOfByte1, int paramInt1, int paramInt2, byte[] paramArrayOfByte2, int paramInt3, int paramInt4)
    throws BadPaddingException
  {
    byte[] arrayOfByte1 = new byte[4];
    byte[] arrayOfByte2 = new byte[mgfMd.getDigestLength()];
    while (paramInt4 > 0)
    {
      mgfMd.update(paramArrayOfByte1, paramInt1, paramInt2);
      mgfMd.update(arrayOfByte1);
      try
      {
        mgfMd.digest(arrayOfByte2, 0, arrayOfByte2.length);
      }
      catch (DigestException localDigestException)
      {
        throw new BadPaddingException(localDigestException.toString());
      }
      for (int i = 0; (i < arrayOfByte2.length) && (paramInt4 > 0); paramInt4--)
      {
        int tmp95_92 = (paramInt3++); byte[] tmp95_88 = paramArrayOfByte2;tmp95_88[tmp95_92] = ((byte)(tmp95_88[tmp95_92] ^ arrayOfByte2[(i++)]));
      }
      if (paramInt4 > 0) {
        for (int i = arrayOfByte1.length - 1;; i--)
        {
          int tmp130_128 = i;
          byte[] tmp130_126 = arrayOfByte1;
          if (((tmp130_126[tmp130_128] = (byte)(tmp130_126[tmp130_128] + 1)) != 0) || (i <= 0)) {
            break;
          }
        }
      }
    }
  }
}