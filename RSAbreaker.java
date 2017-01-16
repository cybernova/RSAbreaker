////////////////
//LICENSE                                                   
////////////////

// Java RSA cracking library VERSION 1.0 Please visit the project's website at: https://github.com/cybernova/RSAbreaker
// Copyright (C) 2017 Andrea Dari (andreadari91@gmail.com)                                   
//                                                                                                       
// This shell script is free software: you can redistribute it and/or modify                             
// it under the terms of the GNU General Public License as published by                                   
// the Free Software Foundation, either version 2 of the License, or                                     
// any later version.                                                                   
//                                                                                                       
// This program is distributed in the hope that it will be useful,                                       
// but WITHOUT ANY WARRANTY; without even the implied warranty of                                        
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the                                         
// GNU General Public License for more details.                                                          
//                                                                                                       
// You should have received a copy of the GNU General Public License                                     
// along with this library.  If not, see <http://www.gnu.org/licenses/>.

import java.math.BigInteger;

public final class RSAbreaker {
	
	private RSAbreaker() {}

	/**
	 * Convert hexadecimal pbKey/pbExp to BigInteger pbKey/pbExp
	 * @param hex pbKey/pbExp in hexadecimal format
	 * @return    pbKey/pbExp in integer format
	 */
	public static BigInteger hexToBigInteger(String hex) {

		String digits = "0123456789ABCDEF";
		hex = hex.toUpperCase();
		BigInteger val = BigInteger.ZERO;
		for (int i = 0; i < hex.length(); i++) {
			char c = hex.charAt(i);
			int d = digits.indexOf(c);
			val = val.multiply(BigInteger.valueOf(16)).add(BigInteger.valueOf(d));
		}
		return val;  	
	}

	/**
	 * Convert BigInteger pbKey/pbExp to hexadecimal pbKey/pbExp
	 * @param key pbKey/pbExp in integer format
	 * @return    pbKey/pbExp in hexadecimal format
	 */
	public static String bigIntegerToHex(BigInteger key) {
		String digits = "0123456789ABCDEF";
		if (key.compareTo(BigInteger.ZERO) == 0) return "0";
		String hex = "";
		while (key.compareTo(BigInteger.ZERO) > 0) {
			BigInteger digit = key.mod(BigInteger.valueOf(16));
			hex = digits.charAt(digit.intValueExact()) + hex;
			key = key.divide(BigInteger.valueOf(16));
		}
		return hex;
	}

	/**
	 * Calculate key length
	 * @param key Public key to crack
	 * @return Public key size in bits
	 */
	public static int keyLength(BigInteger key) {
		return key.bitLength();
	}
	
	/**
	 * Calculate key length
	 * @param hex Public key to crack in hexadecimal format
	 * @return Public key size in bits
	 */
	public static int keyLength(String hex) {
		return hexToBigInteger(hex).bitLength();
	}

	/**
	 * BruteForce cracking algorithm
	 * @param pbKey Public key to crack
	 * @param pbExp Public exponent of the key to crack
	 */
	public static void bruteForce(BigInteger pbKey, BigInteger pbExp) {

		BigInteger p = bigIntSqRootFloor((BigInteger)pbKey);
		while (pbKey.mod(p).compareTo(BigInteger.ZERO) != 0) {
			p = p.subtract(BigInteger.ONE);
		}
		BigInteger q = pbKey.divide(p);
		calcPrivateExp(p, q, pbExp);

	}

	/**
	 * Pollard's Rho cracking algorithm
	 * @param pbKey Public key to crack
	 * @param pbExp Public exponent of the key to crack
	 */
	public static void pollardRho(BigInteger pbKey, BigInteger pbExp) {

		BigInteger p;
		BigInteger x  = new BigInteger("2");
		BigInteger y = x;
		do {
			x = x.multiply(x).add(BigInteger.ONE).mod(pbKey);
			y = y.multiply(y).add(BigInteger.ONE).mod(pbKey);
			y = y.multiply(y).add(BigInteger.ONE).mod(pbKey);
			p = x.subtract(y).gcd(pbKey);
		} while (p.compareTo(BigInteger.ONE) == 0);

		if (p.compareTo(pbKey) == 0)
			return;
		BigInteger q = pbKey.divide(p);
		calcPrivateExp(p, q, pbExp);

	}

	/**
	 * Fermat cracking algorithm
	 * @param pbKey Public key to crack
	 * @param pbExp Public exponent of the key to crack
	 */
	public static void fermat(BigInteger pbKey, BigInteger pbExp) {

		BigInteger a = bigIntSqRootCeil(pbKey);
		BigInteger b2 = a.multiply(a).subtract(pbKey);
		while ( bigIntSqRootCeil(b2).compareTo(bigIntSqRootFloor(b2)) != 0 )
		{
			a = a.add(BigInteger.ONE);
			b2 = a.multiply(a).subtract(pbKey);
		}
		BigInteger p = a.subtract(bigIntSqRootFloor(b2));
		BigInteger q = pbKey.divide(p);
		calcPrivateExp(p, q, pbExp);

	}

	private static void calcPrivateExp(BigInteger p, BigInteger q, BigInteger exp) {

		BigInteger mod = p.subtract(BigInteger.ONE).multiply(q.subtract(BigInteger.ONE));
		BigInteger d = exp.modInverse(mod);
		System.out.println(p + " " + q + " " + d);

	}

	private static BigInteger bigIntSqRootFloor(BigInteger x) throws IllegalArgumentException {
		if (x.compareTo(BigInteger.ZERO) < 0) {
			throw new IllegalArgumentException("Negative argument.");
		}
		if (x.compareTo(BigInteger.ZERO) == 0 || x.compareTo(BigInteger.ONE) == 0) {
			return x;
		}
		BigInteger two = BigInteger.valueOf(2);
		BigInteger y = x.divide(two);
		while (y.compareTo(x.divide(y)) > 0) {
			y = x.divide(y).add(y).divide(two);
		}
		return y;
	}

	private static BigInteger bigIntSqRootCeil(BigInteger x) throws IllegalArgumentException {
		if (x.compareTo(BigInteger.ZERO) < 0) {
			throw new IllegalArgumentException("Negative argument.");
		}
		if (x == BigInteger.ZERO || x == BigInteger.ONE) {
			return x;
		}
		BigInteger two = BigInteger.valueOf(2);
		BigInteger y = x.divide(two);
		while (y.compareTo(x.divide(y)) > 0) {
			y = x.divide(y).add(y).divide(two);
		}
		if (x.compareTo(y.multiply(y)) == 0) {
			return y;
		}
		return y.add(BigInteger.ONE);
	}

}
